"""Strict remote-VM execution protocol and syscall-event analysis.

Samples are only sent to an independently attested VM backend. This module has
no local-process, container, shell, or host-execution fallback.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields
import hashlib
import hmac
import json
from pathlib import Path
import re
import ssl
import tempfile
import time
from typing import Any, Protocol
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class SandboxPolicy:
    isolation: str = "vm"
    network: str = "disabled"
    host_mounts: bool = False
    readonly_base: bool = True
    destroy_after_run: bool = True
    external_watchdog: bool = True
    syscall_monitor_required: bool = True
    timeout_seconds: int = 30
    memory_mb: int = 512
    cpu_count: int = 1
    process_limit: int = 64

    def validate(self) -> list[str]:
        issues = []
        for key in ("host_mounts", "readonly_base", "destroy_after_run", "external_watchdog", "syscall_monitor_required"):
            if type(getattr(self, key)) is not bool:
                issues.append(f"{key} must be a JSON boolean")
        if self.isolation != "vm":
            issues.append("An independent VM execution boundary is required")
        if self.network != "disabled":
            issues.append("This initial policy only supports disabled networking")
        if self.host_mounts is not False:
            issues.append("Host filesystem mounts are forbidden")
        for key in ("readonly_base", "destroy_after_run", "external_watchdog", "syscall_monitor_required"):
            if getattr(self, key) is not True:
                issues.append(f"{key} must be enabled")
        for key, maximum in (("timeout_seconds", 300), ("memory_mb", 8192), ("cpu_count", 4), ("process_limit", 256)):
            value = getattr(self, key)
            if type(value) is not int or not 1 <= value <= maximum:
                issues.append(f"{key} must be an integer between 1 and {maximum}")
        return issues

    @classmethod
    def load(cls, path: str | Path) -> SandboxPolicy:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        unknown = set(data) - {x.name for x in fields(cls)}
        if unknown:
            raise ValueError(f"Unknown sandbox policy keys: {sorted(unknown)}")
        return cls(**data)


REQUIRED_CAPABILITIES: dict[str, Any] = {
    "isolation": "vm",
    "guest_network": "disabled",
    "host_mounts": False,
    "readonly_base": True,
    "ephemeral_overlay": True,
    "external_watchdog": True,
    "syscall_monitor": True,
}
REQUIRED_ACCEPTANCE_TESTS = {
    "network_blocked", "host_fs_hidden", "timeout_kill", "resource_kill",
    "monitor_fail_closed", "overlay_destroyed", "watchdog_survives_disconnect",
    "orphan_recovery", "artifact_integrity",
}
ARTIFACT_NAMES = {"events.jsonl", "stdout.txt", "stderr.txt", "result.json"}
TERMINAL_STATUSES = {"succeeded", "failed", "timed_out", "oom", "policy_violation", "monitor_lost"}


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def validate_attestation(capabilities: dict[str, Any], key: bytes | None = None, *, now: int | None = None) -> list[str]:
    """Validate a structured, expiring backend attestation and optionally its HMAC."""
    issues: list[str] = []
    attestation = capabilities.get("attestation")
    if not isinstance(attestation, dict):
        return ["backend must provide a structured attestation"]
    required_strings = {
        "id", "backend_id", "agent_version", "image_sha256", "kernel_sha256",
        "supervisor_sha256", "acceptance_digest", "signature",
    }
    for name in sorted(required_strings):
        if not isinstance(attestation.get(name), str) or not attestation[name].strip():
            issues.append(f"backend attestation {name} must be a nonempty string")
    for name in ("image_sha256", "kernel_sha256", "supervisor_sha256", "acceptance_digest"):
        value = attestation.get(name)
        if isinstance(value, str) and not re.fullmatch(r"[0-9a-f]{64}", value):
            issues.append(f"backend attestation {name} must be a SHA-256 digest")
    issued_at, expires_at = attestation.get("issued_at"), attestation.get("expires_at")
    if type(issued_at) is not int or type(expires_at) is not int or issued_at >= expires_at:
        issues.append("backend attestation timestamps are invalid")
    else:
        current = int(time.time()) if now is None else now
        if issued_at > current + 60:
            issues.append("backend attestation is issued in the future")
        if expires_at < current:
            issues.append("backend attestation has expired")
        if expires_at - issued_at > 24 * 60 * 60:
            issues.append("backend attestation lifetime exceeds 24 hours")
    if attestation.get("id") != capabilities.get("attestation_id"):
        issues.append("backend attestation id does not match capabilities")
    if attestation.get("backend_id") != capabilities.get("backend_id"):
        issues.append("backend attestation backend_id does not match capabilities")
    if key is not None and isinstance(attestation.get("signature"), str):
        unsigned = {name: value for name, value in attestation.items() if name != "signature"}
        expected = hmac.new(key, _canonical_json(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, attestation["signature"]):
            issues.append("backend attestation signature is invalid")
    return issues


def validate_capabilities(capabilities: dict[str, Any], attestation_key: bytes | None = None) -> list[str]:
    issues = []
    if capabilities.get("quarantined") is True or capabilities.get("execution_ready") is False:
        issues.append("backend is quarantined or explicitly not execution ready")
    for key, expected in REQUIRED_CAPABILITIES.items():
        if capabilities.get(key) != expected:
            issues.append(f"backend capability {key} must equal {expected!r}")
    tests = capabilities.get("acceptance_tests")
    if not isinstance(tests, dict):
        issues.append("backend must provide acceptance_tests")
    else:
        for name in sorted(REQUIRED_ACCEPTANCE_TESTS):
            if tests.get(name) is not True:
                issues.append(f"backend acceptance test {name} must pass")
    if not isinstance(capabilities.get("attestation_id"), str) or not capabilities["attestation_id"].strip():
        issues.append("backend must provide a nonempty attestation_id")
    issues.extend(validate_attestation(capabilities, attestation_key))
    return issues


def preflight(policy: SandboxPolicy, backend_capabilities: dict[str, Any] | None = None) -> dict[str, Any]:
    issues = policy.validate()
    if backend_capabilities is None:
        return {"policy_valid": not issues, "issues": issues, "execution_ready": False,
                "backend": "not_configured", "reason": "Configure an attested independent VM backend; no host fallback exists"}
    backend_issues = validate_capabilities(backend_capabilities)
    return {
        "policy_valid": not issues, "issues": issues, "backend_issues": backend_issues,
        "execution_ready": not issues and not backend_issues,
        "backend": backend_capabilities.get("backend_id", "unknown"),
        "attestation_id": backend_capabilities.get("attestation_id"),
    }


def execute_sample(sample_path, output=None, policy=None, backend=None):
    """Compatibility entry point; execution is impossible without an explicit VM backend."""
    if backend is None or output is None:
        raise RuntimeError("Execution unavailable: configure and validate an independent VM backend first. No host fallback exists.")
    return run_in_vm(sample_path, output, policy or SandboxPolicy(), backend)


class VMBackend(Protocol):
    def capabilities(self) -> dict[str, Any]: ...
    def submit(self, name: str, content: bytes, sha256: str, policy: dict[str, Any]) -> str: ...
    def wait(self, run_id: str, timeout_seconds: int) -> dict[str, Any]: ...
    def artifacts(self, run_id: str) -> dict[str, bytes]: ...
    def destroy(self, run_id: str) -> None: ...


class HttpsVMBackend:
    """Minimal mTLS client for a separately deployed disposable-VM agent."""

    def __init__(self, base_url: str, ca_file: str | Path, cert_file: str | Path, key_file: str | Path,
                 token: str | None = None, attestation_key: bytes | None = None):
        parsed = urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("backend_url must be a credential-free HTTPS origin or path")
        self.base_url = base_url.rstrip("/")
        self.context = ssl.create_default_context(cafile=str(ca_file))
        self.context.load_cert_chain(str(cert_file), str(key_file))
        self.token = token
        if not attestation_key:
            raise ValueError("A trusted backend attestation key is required")
        self.attestation_key = attestation_key

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None,
                 extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra_headers:
            headers.update(extra_headers)
        request = Request(self.base_url + path, data=body, headers=headers, method=method)
        with urlopen(request, context=self.context, timeout=20) as response:
            raw = response.read(24 * 1024 * 1024 + 1)
        if len(raw) > 24 * 1024 * 1024:
            raise ValueError("VM backend response exceeded 24 MiB")
        value = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(value, dict):
            raise ValueError("VM backend response must be a JSON object")
        return value

    def capabilities(self) -> dict[str, Any]:
        capabilities = self._request("GET", "/v1/capabilities")
        issues = validate_attestation(capabilities, self.attestation_key)
        if issues:
            raise ValueError("VM backend attestation failed: " + "; ".join(issues))
        return capabilities

    def submit(self, name: str, content: bytes, sha256: str, policy: dict[str, Any]) -> str:
        request_digest = hashlib.sha256(_canonical_json({"name": name, "sha256": sha256, "policy": policy})).hexdigest()
        response = self._request(
            "POST", "/v1/runs",
            {"name": name, "sha256": sha256, "content_base64": base64.b64encode(content).decode("ascii"), "policy": policy},
            {"Idempotency-Key": request_digest},
        )
        run_id = response.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", run_id):
            raise ValueError("VM backend returned an invalid run_id")
        return run_id

    def wait(self, run_id: str, timeout_seconds: int) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds + 15
        while time.monotonic() < deadline:
            result = self._request("GET", f"/v1/runs/{run_id}")
            if result.get("run_id") not in {None, run_id}:
                raise ValueError("VM backend returned a result for another run")
            if result.get("status") in TERMINAL_STATUSES:
                return result
            if result.get("status") not in {"queued", "running"}:
                raise ValueError("VM backend returned an invalid run status")
            time.sleep(0.5)
        raise TimeoutError("VM backend did not finish within the external deadline")

    def artifacts(self, run_id: str) -> dict[str, bytes]:
        response = self._request("GET", f"/v1/runs/{run_id}/artifacts")
        items = response.get("artifacts")
        if not isinstance(items, list):
            raise ValueError("VM backend artifacts must be a list")
        output = {}
        for item in items:
            if not isinstance(item, dict) or item.get("name") not in ARTIFACT_NAMES:
                raise ValueError("VM backend returned an unexpected artifact")
            try:
                data = base64.b64decode(item.get("content_base64", ""), validate=True)
            except ValueError as exc:
                raise ValueError("VM backend returned invalid artifact encoding") from exc
            if hashlib.sha256(data).hexdigest() != item.get("sha256"):
                raise ValueError("VM backend artifact digest mismatch")
            if item["name"] in output:
                raise ValueError("VM backend returned a duplicate artifact")
            output[item["name"]] = data
        return output

    def destroy(self, run_id: str) -> None:
        response = self._request("DELETE", f"/v1/runs/{run_id}")
        if response.get("destroyed") is not True:
            raise RuntimeError("VM backend did not attest run destruction")


def run_in_vm(
    sample_path: str | Path,
    output: str | Path,
    policy: SandboxPolicy,
    backend: VMBackend,
    *,
    max_sample_bytes: int = 4 * 1024 * 1024,
    max_artifact_bytes: int = 16 * 1024 * 1024,
) -> dict[str, Any]:
    """Run only through a validated backend and always request VM destruction."""
    sample = Path(sample_path)
    content = sample.read_bytes()
    if not content or len(content) > max_sample_bytes:
        raise ValueError(f"sample must contain 1..{max_sample_bytes} bytes")
    capabilities = backend.capabilities()
    readiness = preflight(policy, capabilities)
    if not readiness["execution_ready"]:
        raise RuntimeError("Sandbox preflight failed: " + "; ".join([*readiness["issues"], *readiness.get("backend_issues", [])]))
    sample_hash = hashlib.sha256(content).hexdigest()
    run_id = ""
    report = None
    artifacts: dict[str, bytes] = {}
    event_analysis: dict[str, Any] | None = None
    destroyed = False
    try:
        run_id = backend.submit(sample.name, content, sample_hash, asdict(policy))
        result = backend.wait(run_id, policy.timeout_seconds)
        if not isinstance(result, dict) or result.get("status") not in TERMINAL_STATUSES:
            raise ValueError("VM backend returned an invalid terminal result")
        if result.get("run_id") not in {None, run_id}:
            raise ValueError("VM backend terminal result does not match run_id")
        artifacts = backend.artifacts(run_id)
        if "events.jsonl" not in artifacts:
            raise RuntimeError("VM backend omitted required events.jsonl syscall log")
        if sum(len(value) for value in artifacts.values()) > max_artifact_bytes:
            raise ValueError("VM backend artifacts exceeded the configured limit")
        with tempfile.TemporaryDirectory(prefix="vulntools-events-") as temporary:
            events_path = Path(temporary) / "events.jsonl"
            events_path.write_bytes(artifacts["events.jsonl"])
            event_analysis = analyze_events(events_path, expected_run_id=run_id)
        report = {
            "schema": "vulntools/sandbox-run/v1", "run_id": run_id,
            "sample_sha256": sample_hash, "backend": readiness["backend"],
            "attestation_id": readiness["attestation_id"], "status": result.get("status"),
            "backend_result": result, "event_analysis": event_analysis,
            "artifacts": sorted(artifacts), "execution_boundary": "independent_vm",
        }
    finally:
        if run_id:
            backend.destroy(run_id)
            destroyed = True
    if report is None or not destroyed:
        raise RuntimeError("Sandbox run did not produce a destroyed result")
    output_path = Path(output).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    for name, data in artifacts.items():
        target = (output_path / name).resolve()
        if target.parent != output_path or name not in ARTIFACT_NAMES:
            raise ValueError("Unsafe VM artifact path")
        target.write_bytes(data)
    report["destroyed"] = True
    return report


def analyze_events(path: str | Path, expected_run_id: str | None = None) -> dict[str, Any]:
    from collections import Counter
    counts: Counter = Counter()
    abnormalities = []
    run_ids = set()
    total = 0
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not event.get("run_id") or not event.get("timestamp") or not event.get("type"):
            raise ValueError(f"Event line {line_no} requires run_id, timestamp and type")
        run_ids.add(event["run_id"])
        total += 1
        if event["type"] == "syscall":
            if not event.get("name") or type(event.get("pid")) is not int:
                raise ValueError(f"Syscall line {line_no} requires name and integer pid")
            counts[event["name"]] += 1
            if isinstance(event.get("return_code"), int) and event["return_code"] < 0:
                abnormalities.append({"line": line_no, "run_id": event["run_id"], "kind": "syscall_error", "name": event["name"]})
        elif event["type"] in {"signal", "timeout", "oom", "policy_violation", "monitor_lost"}:
            abnormalities.append({"line": line_no, "run_id": event["run_id"], "kind": event["type"]})
    if expected_run_id is not None and run_ids != {expected_run_id}:
        raise ValueError("Event log run_id does not match the requested run")
    return {"mode": "passive_import", "events": total, "run_ids": sorted(run_ids), "syscall_counts": dict(counts),
            "abnormalities": abnormalities, "isolation_verified": False}
