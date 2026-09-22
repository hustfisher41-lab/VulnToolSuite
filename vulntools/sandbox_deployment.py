"""Read-only execution-node diagnostics and secret-free offline bundle export."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time
import zipfile
from typing import Any

from .models import now
from .sandbox import REQUIRED_ACCEPTANCE_TESTS, _canonical_json


def node_check(config_path: str | Path | None = None, *, dedicated_node: bool = False) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    issues: list[str] = []
    def check(name: str, passed: bool, explanation: str):
        checks[name] = bool(passed)
        if not passed:
            issues.append(explanation)
    linux = sys.platform.startswith("linux")
    check("linux_host", linux, "A dedicated Linux/KVM node is required; Windows is a coordinator only")
    check("dedicated_node_acknowledged", dedicated_node is True,
          "Administrator must confirm this is a dedicated execution node, not a workstation")
    kernel_release = Path("/proc/sys/kernel/osrelease").read_text().lower() if linux else ""
    check("not_wsl", "microsoft" not in kernel_release and "wsl" not in kernel_release and linux,
          "WSL is not the accepted production execution boundary")
    check("not_container", linux and not Path("/.dockerenv").exists() and not Path("/run/.containerenv").exists(),
          "Container-only execution nodes are not accepted")
    kvm_api = False
    if linux and Path("/dev/kvm").exists():
        try:
            import fcntl
            with Path("/dev/kvm").open("r+b", buffering=0) as device:
                kvm_api = fcntl.ioctl(device, 0xAE00, 0) == 12  # KVM_GET_API_VERSION, creates no VM.
        except OSError:
            pass
    check("kvm_api_access", kvm_api, "KVM API 12 must be accessible; diagnostics never create a VM")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    available = set(controllers.read_text().split()) if linux and controllers.is_file() else set()
    check("cgroup_v2_limits_available", {"cpu", "memory", "pids"} <= available,
          "cgroup v2 cpu/memory/pids controllers are required")
    check("systemd_watchdog_tool_available", linux and shutil.which("systemd-run") is not None,
          "Install an independent supervisor watchdog integration; systemd-run not found")
    raw: dict[str, Any] = {}
    if config_path:
        raw = json.loads(Path(config_path).read_text(encoding="utf-8-sig"))
        if not isinstance(raw, dict):
            raise ValueError("Agent configuration must be an object")
    check("production_config_provided", bool(raw), "Provide the actual node's production agent configuration")
    allowed_keys = {"backend_id", "state_dir", "bearer_token_env", "attestation_key_env", "executor",
                    "acceptance_file", "max_sample_bytes", "max_artifact_bytes", "retention_seconds", "workers"}
    check("config_schema", bool(raw) and set(raw) <= allowed_keys,
          "Only documented configuration keys and environment-variable secret references are accepted")
    for name in ("bearer_token", "attestation_key"):
        reference = raw.get(name + "_env")
        value = os.environ.get(reference, "") if isinstance(reference, str) else ""
        check(name + "_environment_ready", len(value.encode()) >= (24 if name == "bearer_token" else 32),
              f"Set the {name} environment variable; values are never printed")
    executor = raw.get("executor") or {}
    if not isinstance(executor, dict):
        executor = {}
    check("production_supervisor_configured", executor.get("type") == "supervisor",
          "Install and independently review the real privileged VM supervisor; no-execution cannot certify a node")
    for label, path_key, hash_key in (("supervisor", "path", "sha256"),
                                      ("image", "image_path", "image_sha256"),
                                      ("kernel", "kernel_path", "kernel_sha256")):
        value, expected = executor.get(path_key), executor.get(hash_key)
        configured = isinstance(value, str) and isinstance(expected, str) and bool(re.fullmatch(r"[0-9a-f]{64}", expected))
        verified = False
        if configured and linux:
            path = Path(value)
            if path.is_absolute() and path.is_file():
                stat = path.stat()
                hashed = hashlib.sha256()
                with path.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        hashed.update(block)
                verified = stat.st_uid == 0 and not stat.st_mode & 0o022 and hashed.hexdigest() == expected
        check(label + "_root_owned_pin_valid", verified, f"Provide root-owned, non-writable, hash-pinned {label} on the Linux node")
    signed_acceptance = False
    path_value = raw.get("acceptance_file")
    if isinstance(path_value, str) and linux and Path(path_value).is_file():
        record = json.loads(Path(path_value).read_text(encoding="utf-8"))
        if isinstance(record, dict):
            signature = record.get("signature")
            unsigned = {name: value for name, value in record.items() if name != "signature"}
            env_name = raw.get("attestation_key_env")
            key = os.environ.get(env_name, "").encode() if isinstance(env_name, str) else b""
            expected = hmac.new(key, _canonical_json(unsigned), hashlib.sha256).hexdigest()
            identity = {"supervisor_sha256": executor.get("sha256"), "image_sha256": executor.get("image_sha256"),
                        "kernel_sha256": executor.get("kernel_sha256")}
            tested_at = unsigned.get("tested_at")
            tests = unsigned.get("acceptance_tests")
            signed_acceptance = (bool(key) and isinstance(signature, str) and hmac.compare_digest(signature, expected)
                                 and unsigned.get("executor_identity") == identity and type(tested_at) is int
                                 and -60 <= time.time() - tested_at <= 30 * 24 * 60 * 60
                                 and isinstance(tests, dict)
                                 and all(tests.get(name) is True for name in REQUIRED_ACCEPTANCE_TESTS))
    check("signed_real_acceptance_valid", signed_acceptance, "Nine actual-node isolation tests must pass with a fresh signed, identity-bound record")
    return {"schema": "vulntools/sandbox-node-check/v1", "created_at": now(), "platform": sys.platform,
            "checks": checks, "issues": issues, "mechanical_checks_passed": all(checks.values()),
            "execution_ready": False, "sample_executed": False, "node_started": False,
            "note": "Read-only diagnostics are not isolation acceptance or backend connectivity proof. Agent preflight is still mandatory."}


def build_node_bundle(output: str | Path) -> dict[str, Any]:
    project = Path(__file__).resolve().parent.parent
    if not (project / "pyproject.toml").is_file():
        raise RuntimeError("Bundle export must run from the reviewed source checkout")
    directory = Path(output).resolve() / ("bundle_" + secrets.token_hex(8))
    directory.mkdir(parents=True, exist_ok=False)
    selected = [(project / "pyproject.toml", "code/pyproject.toml"),
                (project / "README.md", "code/README.md")]
    selected.extend((path, "code/" + path.relative_to(project).as_posix())
                    for path in sorted((project / "vulntools").rglob("*.py")))
    for name in ("systemd/vulntools-sandbox-agent.service", "systemd/vulntools-guest-monitor.service",
                 "install-sandbox-node.sh", "verify-node-bundle.py"):
        path = project / "deployment" / name
        selected.append((path, "deployment/" + name))
    selected.extend((path, path.relative_to(project).as_posix())
                    for path in sorted((project / "docs").glob("sandbox*.md")))
    selected.extend((project / "examples" / name, "examples/" + name)
                    for name in ("sandbox-agent.example.json", "sandbox-policy.json"))
    manifest = {"schema": "vulntools/sandbox-node-bundle/v1", "created_at": now(),
                "status": "offline_deployment_assets_only", "files": {}, "contains_secrets": False,
                "execution_ready": False, "node_installed": False,
                "external_prerequisites": ["Dedicated Linux/KVM node", "Offline dependency wheels",
                                           "Independently reviewed privileged Firecracker supervisor/service",
                                           "Built and reviewed canary guest rootfs and kernel",
                                           "Private CA, mTLS certificates and secrets", "Nine real isolation acceptance tests"]}
    archive = directory / "sandbox-node-bundle.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for path, name in selected:
            if path.is_symlink() or not path.resolve().is_relative_to(project):
                raise ValueError("Bundle source must not escape the project or be a symlink")
            data = path.read_bytes()
            manifest["files"][name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            package.writestr(name, data)
        package.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    manifest["archive"] = {"path": str(archive), "bytes": archive.stat().st_size,
                           "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    (directory / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest
