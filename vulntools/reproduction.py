"""Small reproduction commissioning workflow; never executes samples on the host.

The fixture backend fabricates protocol responses, not vulnerability evidence.
Real execution uses the existing attested VM protocol. Neither path promotes
PoC review status or changes the source database.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any

from .models import now
from .sandbox import (REQUIRED_ACCEPTANCE_TESTS, REQUIRED_CAPABILITIES,
                      SandboxPolicy, VMBackend, preflight, run_in_vm)

SCHEMA = "vulntools/reproduction-smoke/v1"
VARIANTS = {"boundary_missing": "authz_missing.py", "boundary_enforced": "authz_enforced.py"}
PIN_NAMES = ("image_sha256", "kernel_sha256", "supervisor_sha256")


def _save(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def candidate_plan(database: str | Path, *, limit: int = 3) -> dict[str, Any]:
    """Read-only selection, metadata only; never export or run candidate code."""
    if type(limit) is not int or not 1 <= limit <= 10:
        raise ValueError("limit must be between 1 and 10")
    path = Path(database).resolve(strict=True)
    selected, seen = [], set()
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as db:
        rows = db.execute("""SELECT c.vuln_id,c.revision,c.payload,a.artifact_id,a.title,
            a.source_url,a.commit_ref,a.language,a.current_content_sha256,a.metadata,a.review_status
            FROM canonical c JOIN poc_vulnerability_links l ON l.vuln_id=c.vuln_id
            JOIN poc_artifacts a ON a.artifact_id=l.artifact_id
            WHERE a.artifact_type='exploit_code' AND a.review_status IN ('candidate','static_reviewed')
              AND json_extract(c.payload,'$.status')='active'
              AND lower(a.title) NOT LIKE '%kernel%'
              AND lower(json_extract(c.payload,'$.fields.description')) NOT LIKE '%kernel%'
              AND lower(a.title) NOT LIKE '%privilege escalation%'
              AND lower(a.title) NOT LIKE '%remote code execution%'
              AND lower(a.title) NOT LIKE '%buffer over%'
              AND lower(json_extract(c.payload,'$.fields.description')) NOT LIKE '%execute arbitrary code%'
              AND lower(json_extract(c.payload,'$.fields.description')) NOT LIKE '%gain privilege%'
            ORDER BY CASE WHEN lower(a.title) LIKE '%information disclosure%'
                            OR lower(a.title) LIKE '%directory traversal%'
                            OR lower(a.title) LIKE '%cross-site scripting%' THEN 0 ELSE 1 END,
                     CASE WHEN lower(json_extract(a.metadata,'$.platform'))='linux' THEN 0 ELSE 1 END,
                     CASE WHEN a.language='python' THEN 0 ELSE 1 END,c.vuln_id,a.artifact_id""")
        for row in rows:
            if row[0] in seen:
                continue
            record, metadata = json.loads(row[2]), json.loads(row[9])
            text = (row[4] + " " + str(record.get("fields", {}).get("description") or "")).lower()
            risk_hints = [label for label, hints in (
                ("kernel_requires_separate_pool", ("kernel",)),
                ("privilege_escalation", ("privilege escalation", "gain privilege")),
                ("code_execution_or_memory_corruption", ("execute arbitrary code", "remote code execution", "buffer overflow", "buffer overrun")),
                ("availability_impact", ("denial of service",)),
            ) if any(hint in text for hint in hints)]
            seen.add(row[0])
            selected.append({"vuln_id": row[0], "record_revision": row[1],
                             "description": record.get("fields", {}).get("description"),
                             "source_asserted_components": record.get("fields", {}).get("components"),
                             "artifact_id": row[3], "title": row[4], "source_url": row[5],
                             "commit_ref": row[6], "language": row[7], "content_sha256": row[8],
                             "upstream_platform": metadata.get("platform"), "review_status": row[10],
                             "risk_hints": risk_hints, "hints_are_verified": False,
                             "network_fit": "unknown; current VM policy has no NIC",
                             "status": "awaiting_audited_recipe", "execution_ready": False,
                             "blockers": ["Review code and confirm affected version and dependencies",
                                          "Pin vulnerable and fixed guest images",
                                          "Define independent effect oracle and negative controls",
                                          "Provision and commission independent VM backend"],
                             "real_vulnerability_verified": False})
            if len(selected) >= limit:
                break
    return {"schema": "vulntools/reproduction-candidates/v1", "created_at": now(),
            "database": str(path), "selection": "prefer observable-effect title hints, then Linux/Python; not compatibility or safety proof",
            "initial_pool_exclusions": "explicit kernel, privilege escalation and remote code execution/memory corruption hints",
            "count": len(selected), "candidates": selected, "code_executed": False,
            "database_updated": False}


def _observation(variant: str, nonce: str) -> dict[str, Any]:
    return {"schema": "vulntools/canary-observation/v1", "case_id": "authz-canary",
            "nonce": nonce, "variant": variant, "actor": "observer", "owner": "owner",
            "access_allowed": variant == "boundary_missing",
            "marker_observed": variant == "boundary_missing"}


class _FixtureBackend:
    """Protocol simulation only: does not compile, import or execute samples."""
    def __init__(self, nonce: str):
        self.nonce = nonce
        self.runs: dict[str, dict[str, Any]] = {}

    def capabilities(self):
        timestamp = int(time.time())
        return {**REQUIRED_CAPABILITIES, "backend_id": "fixture-no-execution",
                "attestation_id": "fixture-not-trusted",
                "acceptance_tests": {name: True for name in REQUIRED_ACCEPTANCE_TESTS},
                "attestation": {"id": "fixture-not-trusted", "backend_id": "fixture-no-execution",
                                "agent_version": "fixture", **{name: "0" * 64 for name in PIN_NAMES},
                                "acceptance_digest": "0" * 64, "signature": "not-a-real-signature",
                                "issued_at": timestamp, "expires_at": timestamp + 120}}

    def submit(self, name, content, sha256, policy):
        variant = next((key for key, filename in VARIANTS.items() if filename == name), None)
        if variant is None or hashlib.sha256(content).hexdigest() != sha256:
            raise ValueError("Invalid canary fixture submission")
        run_id = "fixture_" + secrets.token_hex(16)
        self.runs[run_id] = {"variant": variant, "sha256": sha256, "destroyed": False}
        return run_id

    def wait(self, run_id, timeout_seconds):
        return {"run_id": run_id, "status": "succeeded", "exit_code": 0}

    def artifacts(self, run_id):
        item = self.runs[run_id]
        runtime = {"run_id": run_id, "sample_sha256": item["sha256"], "exit_code": 0}
        event = {"run_id": run_id, "timestamp": now(), "type": "syscall", "name": "write", "pid": 1}
        return {"stdout.txt": (json.dumps(_observation(item["variant"], self.nonce)) + "\n").encode(),
                "stderr.txt": b"", "result.json": json.dumps(runtime).encode(),
                "events.jsonl": (json.dumps(event) + "\n").encode()}

    def destroy(self, run_id):
        self.runs[run_id]["destroyed"] = True


class _PinnedBackend:
    def __init__(self, backend: VMBackend, pins: dict[str, str]):
        self.backend, self.pins = backend, pins
        self.latest_capabilities: dict[str, Any] = {}
        self.last_run_id: str | None = None
        self.destroyed = False

    def capabilities(self):
        capabilities = self.backend.capabilities()
        attestation = capabilities.get("attestation") or {}
        for name, expected in self.pins.items():
            if attestation.get(name) != expected:
                raise ValueError(f"VM recipe pin mismatch: {name}")
        self.latest_capabilities = capabilities
        return capabilities

    def submit(self, *args):
        self.last_run_id = self.backend.submit(*args)
        self.destroyed = False
        return self.last_run_id

    def wait(self, *args):
        return self.backend.wait(*args)

    def artifacts(self, *args):
        return self.backend.artifacts(*args)

    def destroy(self, *args):
        result = self.backend.destroy(*args)
        self.destroyed = True
        return result


def check_canary(report: dict[str, Any], directory: Path, variant: str, nonce: str) -> dict[str, Any]:
    """Check runtime evidence and synthetic effect, never certify a real CVE."""
    issues = []
    if report.get("status") != "succeeded" or report.get("destroyed") is not True:
        issues.append("runtime_unsuccessful_or_not_destroyed")
    analysis = report.get("event_analysis") or {}
    critical = [item for item in analysis.get("abnormalities") or [] if item.get("kind") != "syscall_error"]
    if not analysis.get("syscall_counts") or critical:
        issues.append("monitor_missing_or_abnormal")
    evidence_hashes = {}
    for name in ("stdout.txt", "stderr.txt", "result.json", "events.jsonl"):
        path = directory / name
        if not path.is_file():
            issues.append(f"missing_evidence:{name}")
        else:
            evidence_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    try:
        runtime = json.loads((directory / "result.json").read_text(encoding="utf-8"))
        if (runtime.get("run_id") != report["run_id"]
                or runtime.get("sample_sha256") != report["sample_sha256"]
                or type(runtime.get("exit_code")) is not int or runtime["exit_code"] != 0):
            issues.append("runtime_evidence_binding_or_exit_mismatch")
        observed = json.loads((directory / "stdout.txt").read_text(encoding="utf-8"))
        expected = _observation(variant, nonce)
        if observed != expected or any(type(observed.get(key)) is not bool
                                       for key in ("access_allowed", "marker_observed")):
            issues.append("synthetic_effect_not_confirmed")
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        issues.append("invalid_or_missing_runtime_evidence")
    return {"variant": variant, "status": "passed" if not issues else "failed",
            "issues": issues, "evidence_sha256": evidence_hashes,
            "syscall_error_count": sum(item.get("kind") == "syscall_error" for item in analysis.get("abnormalities") or []),
            "real_vulnerability_verified": False}


def smoke_workflow(output: str | Path, *, mode: str = "plan", policy: SandboxPolicy | None = None,
                   backend: VMBackend | None = None, pins: dict[str, str] | None = None) -> dict[str, Any]:
    if mode not in {"plan", "fixture", "vm"}:
        raise ValueError("mode must be plan, fixture or vm")
    if mode != "vm" and (backend is not None or pins):
        raise ValueError("Backend and environment pins are only accepted in vm mode")
    if mode == "vm" and (not isinstance(pins, dict) or set(pins) != set(PIN_NAMES)
                         or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                                for value in pins.values())):
        raise ValueError("vm mode requires image, kernel and supervisor SHA-256 pins")
    policy = policy or SandboxPolicy()
    if policy.validate():
        raise ValueError("Unsafe canary policy: " + "; ".join(policy.validate()))
    nonce = secrets.token_hex(16)
    directory = Path(output).resolve() / ("attempt_" + nonce)
    sample_dir = directory / "samples"
    sample_dir.mkdir(parents=True, exist_ok=False)
    samples = []
    for variant, filename in VARIANTS.items():
        source = Path(__file__).parent / "canaries" / filename
        original = source.read_bytes()
        if original.count(b"__PROBE_NONCE__") != 1:
            raise ValueError("Invalid built-in canary source")
        content = original.replace(b"__PROBE_NONCE__", nonce.encode("ascii"))
        destination = sample_dir / filename
        destination.write_bytes(content)
        samples.append({"variant": variant, "path": str(destination),
                        "source_sha256": hashlib.sha256(original).hexdigest(),
                        "sample_sha256": hashlib.sha256(content).hexdigest(),
                        "expected_observation": _observation(variant, nonce)})
    plan = {"schema": SCHEMA, "case_id": "authz-canary", "nonce": nonce,
            "kind": "harmless_synthetic_workflow_canary", "samples": samples,
            "policy": asdict(policy), "environment_pins": pins,
            "guest_requirements": ["Python 3 standard library", "trusted monitor before sample execution",
                                   "no NIC, host mounts, credentials or production data"],
            "oracle": "missing-boundary allows dummy marker; enforced-boundary denies it",
            "real_vulnerability_verified": False}
    _save(directory / "plan.json", plan)
    report = {"schema": SCHEMA, "created_at": now(), "mode": mode, "directory": str(directory),
              "recipe_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
              "nonce": nonce, "status": "planned", "runs": [], "issues": [],
              "sample_executed": False, "real_vulnerability_verified": False,
              "execution_ready": False,
              "database_updated": False, "is_simulated": mode == "fixture",
              "note": "Synthetic workflow only, not real-CVE reproduction or isolation certification."}
    if mode == "plan" or (mode == "vm" and backend is None):
        report["status"] = "planned" if mode == "plan" else "blocked"
        report["issues"] = ["Configure attested VM backend and pinned guest environment"]
    else:
        active = _FixtureBackend(nonce) if mode == "fixture" else backend
        pinned = _PinnedBackend(active, {name: "0" * 64 for name in PIN_NAMES} if mode == "fixture" else pins)
        try:
            capabilities = pinned.capabilities()
            readiness = preflight(policy, capabilities)
            if not readiness["execution_ready"]:
                raise RuntimeError("VM capability or policy preflight failed")
            report["backend"] = capabilities["backend_id"]
            report["execution_ready"] = mode == "vm"
            for sample in samples:
                path = Path(sample["path"])
                if hashlib.sha256(path.read_bytes()).hexdigest() != sample["sample_sha256"]:
                    raise ValueError("Canary sample changed before submission")
                variant_dir = directory / sample["variant"]
                run = run_in_vm(path, variant_dir, policy, pinned)
                report["sample_executed"] = mode == "vm"
                _save(variant_dir / "run-report.json", {**run, "is_simulated": mode == "fixture"})
                verdict = check_canary(run, variant_dir, sample["variant"], nonce)
                report["runs"].append({"run_id": run["run_id"], "sample_sha256": run["sample_sha256"],
                                       "destroyed": run["destroyed"], "verdict": verdict})
            report["status"] = ("fixture_passed" if mode == "fixture" else "canary_passed") if (
                len(report["runs"]) == 2 and all(item["verdict"]["status"] == "passed" for item in report["runs"])
            ) else "not_confirmed"
        except Exception as exc:
            report["status"] = "blocked_or_failed"
            report["issues"].append(str(exc))
            if pinned.last_run_id:
                report["last_submission"] = {"run_id": pinned.last_run_id,
                                             "destruction_confirmed": pinned.destroyed}
                if mode == "vm":
                    report["sample_executed"] = None
            report["note"] += " A submitted VM run may have failed; inspect the backend audit log."
    _save(directory / "verification-report.json", report)
    return report
