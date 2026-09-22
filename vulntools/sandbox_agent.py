"""Control service for a separately deployed disposable-VM supervisor.

This module never executes a submitted sample as a host process.  The production
executor delegates to one pinned supervisor binary whose job is to create and
destroy the VM, talk to the guest agent, and return allow-listed artifacts.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any, Protocol
from uuid import uuid4

from .sandbox import (
    ARTIFACT_NAMES, REQUIRED_ACCEPTANCE_TESTS, SandboxPolicy, TERMINAL_STATUSES,
    _canonical_json,
)


AGENT_VERSION = "0.2.0"
RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{8,128}")
IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{16,128}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


class VMExecutor(Protocol):
    production_ready: bool

    def identity(self) -> dict[str, str]: ...
    def run(self, run_id: str, sample: Path, policy: SandboxPolicy, artifact_dir: Path) -> dict[str, Any]: ...
    def destroy(self, run_id: str) -> None: ...
    def acceptance(self) -> dict[str, bool]: ...


@dataclass(frozen=True)
class SupervisorExecutor:
    """Adapter for an independently installed and hash-pinned VM supervisor."""

    supervisor_path: Path
    supervisor_sha256: str
    image_path: Path
    image_sha256: str
    kernel_path: Path
    kernel_sha256: str
    state_dir: Path
    production_ready: bool = field(default=True, init=False)

    def __post_init__(self) -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimeError("The production VM supervisor is supported only on a dedicated Linux execution node")
        for path, expected, label in (
            (self.supervisor_path, self.supervisor_sha256, "supervisor"),
            (self.image_path, self.image_sha256, "image"),
            (self.kernel_path, self.kernel_sha256, "kernel"),
        ):
            resolved = path.resolve(strict=True)
            if not resolved.is_file() or not SHA256_PATTERN.fullmatch(expected):
                raise ValueError(f"Invalid pinned {label} configuration")
            if _sha256_file(resolved) != expected:
                raise ValueError(f"Pinned {label} digest does not match")
            stat = resolved.stat()
            if stat.st_uid != 0 or stat.st_mode & 0o022:
                raise ValueError(f"Pinned {label} must be root-owned and not group/other writable")
            object.__setattr__(self, f"{label}_path", resolved)
        if os.geteuid() == 0:
            raise RuntimeError("sandbox-agent must run as a dedicated unprivileged account, not root")

    def identity(self) -> dict[str, str]:
        return {
            "supervisor_sha256": self.supervisor_sha256,
            "image_sha256": self.image_sha256,
            "kernel_sha256": self.kernel_sha256,
        }

    def _verify_pins(self) -> None:
        for path, expected, label in (
            (self.supervisor_path, self.supervisor_sha256, "supervisor"),
            (self.image_path, self.image_sha256, "image"),
            (self.kernel_path, self.kernel_sha256, "kernel"),
        ):
            if _sha256_file(path) != expected:
                raise RuntimeError(f"Pinned {label} changed after agent startup")

    def _call(self, arguments: list[str], timeout: int) -> dict[str, Any]:
        if _sha256_file(self.supervisor_path) != self.supervisor_sha256:
            raise RuntimeError("Pinned supervisor changed after agent startup")
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        completed = subprocess.run(
            [str(self.supervisor_path), *arguments], check=False, shell=False,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout, env=environment, cwd=str(self.state_dir),
        )
        if completed.returncode != 0:
            message = completed.stderr[-2000:].strip() or f"exit {completed.returncode}"
            raise RuntimeError(f"VM supervisor failed: {message}")
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("VM supervisor returned invalid JSON") from exc
        if not isinstance(value, dict):
            raise RuntimeError("VM supervisor result must be a JSON object")
        return value

    def run(self, run_id: str, sample: Path, policy: SandboxPolicy, artifact_dir: Path) -> dict[str, Any]:
        self._verify_pins()
        spec = sample.parent / "run-spec.json"
        spec.write_text(json.dumps({
            "schema": "vulntools/supervisor-run/v1", "run_id": run_id,
            "sample_path": str(sample), "sample_sha256": _sha256_file(sample),
            "artifact_dir": str(artifact_dir), "kernel_path": str(self.kernel_path),
            "image_path": str(self.image_path), "policy": asdict(policy),
        }, sort_keys=True), encoding="utf-8")
        return self._call(["run", "--spec", str(spec)], policy.timeout_seconds + 30)

    def destroy(self, run_id: str) -> None:
        result = self._call(["destroy", "--run-id", run_id], 30)
        if result.get("destroyed") is not True:
            raise RuntimeError("VM supervisor did not confirm destruction")

    def acceptance(self) -> dict[str, bool]:
        self._verify_pins()
        result = self._call(["acceptance", "--state-dir", str(self.state_dir)], 300)
        tests = result.get("acceptance_tests")
        if not isinstance(tests, dict):
            raise RuntimeError("VM supervisor omitted acceptance tests")
        return {name: tests.get(name) is True for name in REQUIRED_ACCEPTANCE_TESTS}


@dataclass(frozen=True)
class NoExecutionExecutor:
    """Safe local mode for API/CI validation; it never opens or executes samples."""

    production_ready: bool = field(default=False, init=False)

    def identity(self) -> dict[str, str]:
        empty = hashlib.sha256(b"no-production-executor").hexdigest()
        return {"supervisor_sha256": empty, "image_sha256": empty, "kernel_sha256": empty}

    def run(self, run_id: str, sample: Path, policy: SandboxPolicy, artifact_dir: Path) -> dict[str, Any]:
        raise RuntimeError("No production VM executor is configured; host execution is forbidden")

    def destroy(self, run_id: str) -> None:
        return None

    def acceptance(self) -> dict[str, bool]:
        return {name: False for name in REQUIRED_ACCEPTANCE_TESTS}


@dataclass(frozen=True)
class AgentConfig:
    backend_id: str
    state_dir: Path
    bearer_token: str
    attestation_key: bytes
    executor: VMExecutor
    acceptance_tests: dict[str, bool] = field(default_factory=dict)
    max_sample_bytes: int = 4 * 1024 * 1024
    max_artifact_bytes: int = 16 * 1024 * 1024
    retention_seconds: int = 24 * 60 * 60
    workers: int = 2
    acceptance_expires_at: int | None = None

    def validate(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", self.backend_id):
            raise ValueError("backend_id must contain 3..64 safe characters")
        if len(self.bearer_token) < 24:
            raise ValueError("A bearer token of at least 24 characters is required")
        if len(self.attestation_key) < 32:
            raise ValueError("An attestation key of at least 32 bytes is required")
        for name, maximum in (("workers", 16), ("max_sample_bytes", 64 * 1024 * 1024),
                              ("max_artifact_bytes", 16 * 1024 * 1024), ("retention_seconds", 30 * 24 * 60 * 60)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"{name} must be an integer in 1..{maximum}")
        if self.acceptance_expires_at is not None and type(self.acceptance_expires_at) is not int:
            raise ValueError("acceptance_expires_at must be an integer")
        self.state_dir.resolve().mkdir(parents=True, exist_ok=True)


class AgentStore:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        with self._connect() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    name TEXT NOT NULL,
                    sample_sha256 TEXT NOT NULL,
                    policy_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    destroyed INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    timestamp TEXT NOT NULL,
                    event TEXT NOT NULL,
                    detail_json TEXT NOT NULL
                );
            """)

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def audit(self, run_id: str | None, event: str, detail: dict[str, Any] | None = None) -> None:
        with self.lock, self._connect() as db:
            db.execute("INSERT INTO audit(run_id,timestamp,event,detail_json) VALUES(?,?,?,?)",
                       (run_id, _utc_now(), event, json.dumps(detail or {}, sort_keys=True)))

    def reserve(self, idempotency_key: str, request_digest: str, name: str, sample_sha256: str,
                policy: SandboxPolicy) -> tuple[str, bool]:
        with self.lock, self._connect() as db:
            existing = db.execute("SELECT run_id,request_digest FROM runs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if existing:
                if existing["request_digest"] != request_digest:
                    raise ValueError("Idempotency key was already used for a different request")
                return existing["run_id"], False
            run_id = "run_" + uuid4().hex
            now = time.time()
            db.execute("""INSERT INTO runs(run_id,idempotency_key,request_digest,name,sample_sha256,
                       policy_json,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                       (run_id, idempotency_key, request_digest, name, sample_sha256,
                        json.dumps(asdict(policy), sort_keys=True), "queued", now, now))
            return run_id, True

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return dict(row) if row else None

    def update(self, run_id: str, status: str, *, result: dict[str, Any] | None = None,
               error: str | None = None, destroyed: bool | None = None) -> None:
        assignments, values = ["status=?", "updated_at=?"], [status, time.time()]
        if result is not None:
            assignments.append("result_json=?")
            values.append(json.dumps(result, sort_keys=True))
        if error is not None:
            assignments.append("error=?")
            values.append(error[:4000])
        if destroyed is not None:
            assignments.append("destroyed=?")
            values.append(int(destroyed))
        values.append(run_id)
        with self.lock, self._connect() as db:
            db.execute(f"UPDATE runs SET {','.join(assignments)} WHERE run_id=?", values)

    def active(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM runs WHERE status IN ('queued','running')")]

    def expired(self, cutoff: float) -> list[dict[str, Any]]:
        with self._connect() as db:
            return [dict(row) for row in db.execute("SELECT * FROM runs WHERE updated_at<?", (cutoff,))]


class SandboxAgent:
    def __init__(self, config: AgentConfig):
        config.validate()
        self.config = config
        self.root = config.state_dir.resolve()
        self.runs_dir = self.root / "runs"
        self.runs_dir.mkdir(exist_ok=True)
        self.quarantine_path = self.root / "QUARANTINED"
        self.store = AgentStore(self.root / "agent.sqlite")
        self.pool = ThreadPoolExecutor(max_workers=config.workers, thread_name_prefix="sandbox-vm")
        self._reconcile()
        self.cleanup_expired()

    @property
    def quarantined(self) -> bool:
        return self.quarantine_path.exists()

    def _quarantine(self, run_id: str, reason: str) -> None:
        self.quarantine_path.write_text(f"{_utc_now()} {run_id} {reason}\n", encoding="utf-8")
        self.store.audit(run_id, "agent_quarantined", {"reason": reason})

    def _reconcile(self) -> None:
        for row in self.store.active():
            run_id = row["run_id"]
            try:
                self.config.executor.destroy(run_id)
                self.store.update(run_id, "failed", error="Agent restarted during run", destroyed=True)
                self.store.audit(run_id, "orphan_recovered")
            except Exception as exc:
                self.store.update(run_id, "failed", error=f"Orphan cleanup failed: {exc}")
                self._quarantine(run_id, f"orphan cleanup failed: {exc}")

    def cleanup_expired(self) -> None:
        cutoff = time.time() - self.config.retention_seconds
        for row in self.store.expired(cutoff):
            if not row["destroyed"]:
                continue
            run_dir = (self.runs_dir / row["run_id"]).resolve()
            if run_dir.parent == self.runs_dir:
                shutil.rmtree(run_dir, ignore_errors=True)

    def capabilities(self) -> dict[str, Any]:
        tests = {name: self.config.acceptance_tests.get(name) is True for name in REQUIRED_ACCEPTANCE_TESTS}
        identity = self.config.executor.identity()
        current = self.config.acceptance_expires_at is None or time.time() < self.config.acceptance_expires_at
        accepted = self.config.executor.production_ready and current and all(tests.get(name) is True for name in REQUIRED_ACCEPTANCE_TESTS)
        issued_at = int(time.time())
        expires_at = issued_at + 300
        if accepted and self.config.acceptance_expires_at is not None:
            expires_at = min(expires_at, self.config.acceptance_expires_at)
        acceptance_digest = hashlib.sha256(_canonical_json(tests)).hexdigest()
        attestation_id = f"att_{issued_at}_{acceptance_digest[:16]}"
        unsigned = {
            "id": attestation_id, "backend_id": self.config.backend_id,
            "agent_version": AGENT_VERSION, "issued_at": issued_at, "expires_at": expires_at,
            **identity, "acceptance_digest": acceptance_digest,
        }
        attestation = {**unsigned, "signature": hmac.new(
            self.config.attestation_key, _canonical_json(unsigned), hashlib.sha256).hexdigest()}
        return {
            "backend_id": self.config.backend_id, "attestation_id": attestation_id,
            "isolation": "vm" if accepted else "unavailable",
            "guest_network": "disabled", "host_mounts": False, "readonly_base": True,
            "ephemeral_overlay": accepted, "external_watchdog": accepted,
            "syscall_monitor": accepted, "acceptance_tests": tests,
            "attestation": attestation, "quarantined": self.quarantined,
            "execution_ready": accepted and not self.quarantined,
        }

    def submit(self, body: dict[str, Any], idempotency_key: str) -> str:
        if self.quarantined:
            raise RuntimeError("Sandbox node is quarantined after a destruction failure")
        if ((self.config.acceptance_expires_at is not None and time.time() >= self.config.acceptance_expires_at)
                or not self.config.executor.production_ready or not all(
            self.config.acceptance_tests.get(name) is True for name in REQUIRED_ACCEPTANCE_TESTS
        )):
            raise RuntimeError("Sandbox node has no current passing production acceptance record")
        if not IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
            raise ValueError("Idempotency-Key must contain 16..128 safe characters")
        allowed = {"name", "sha256", "content_base64", "policy"}
        if set(body) != allowed:
            raise ValueError("Run request has missing or unknown fields")
        name = body.get("name")
        if not isinstance(name, str) or not name or len(name) > 200 or Path(name).name != name:
            raise ValueError("Sample name must be a safe basename")
        sample_sha256 = body.get("sha256")
        if not isinstance(sample_sha256, str) or not SHA256_PATTERN.fullmatch(sample_sha256):
            raise ValueError("Sample sha256 is invalid")
        try:
            content = base64.b64decode(body.get("content_base64", ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("Sample content_base64 is invalid") from exc
        if not 1 <= len(content) <= self.config.max_sample_bytes:
            raise ValueError("Sample size is outside the configured limit")
        if hashlib.sha256(content).hexdigest() != sample_sha256:
            raise ValueError("Sample digest mismatch")
        raw_policy = body.get("policy")
        if not isinstance(raw_policy, dict):
            raise ValueError("policy must be an object")
        unknown = set(raw_policy) - {item.name for item in fields(SandboxPolicy)}
        if unknown:
            raise ValueError(f"Unknown policy keys: {sorted(unknown)}")
        policy = SandboxPolicy(**raw_policy)
        issues = policy.validate()
        if issues:
            raise ValueError("Unsafe policy: " + "; ".join(issues))
        request_digest = hashlib.sha256(_canonical_json({
            "name": name, "sha256": sample_sha256, "policy": asdict(policy),
        })).hexdigest()
        run_id, created = self.store.reserve(idempotency_key, request_digest, name, sample_sha256, policy)
        if not created:
            return run_id
        run_dir = (self.runs_dir / run_id).resolve()
        if run_dir.parent != self.runs_dir:
            raise RuntimeError("Unsafe run directory")
        artifact_dir = run_dir / "artifacts"
        artifact_dir.mkdir(parents=True)
        sample = run_dir / "sample.bin"
        sample.write_bytes(content)
        self.store.audit(run_id, "run_queued", {"sample_sha256": sample_sha256})
        self.pool.submit(self._worker, run_id, sample, policy, artifact_dir)
        return run_id

    def _validate_artifacts(self, run_id: str, artifact_dir: Path) -> list[dict[str, Any]]:
        items, total = [], 0
        for path in artifact_dir.iterdir():
            if not path.is_file() or path.name not in ARTIFACT_NAMES or path.resolve().parent != artifact_dir.resolve():
                raise RuntimeError("VM supervisor returned an unexpected artifact")
            size = path.stat().st_size
            total += size
            if total > self.config.max_artifact_bytes:
                raise RuntimeError("VM artifacts exceeded the configured limit")
            items.append({"name": path.name, "size": size, "sha256": _sha256_file(path)})
        if "events.jsonl" not in {item["name"] for item in items}:
            raise RuntimeError("VM supervisor omitted events.jsonl")
        # Bind every event to this run before artifacts become downloadable.
        for line_number, line in enumerate((artifact_dir / "events.jsonl").read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("run_id") != run_id:
                raise RuntimeError(f"Event line {line_number} is not bound to this run")
        return sorted(items, key=lambda item: item["name"])

    def _worker(self, run_id: str, sample: Path, policy: SandboxPolicy, artifact_dir: Path) -> None:
        self.store.update(run_id, "running")
        self.store.audit(run_id, "run_started")
        status, result, error = "failed", None, None
        try:
            result = self.config.executor.run(run_id, sample, policy, artifact_dir)
            status = result.get("status") if isinstance(result, dict) else None
            if status not in TERMINAL_STATUSES:
                raise RuntimeError("VM supervisor returned an invalid terminal status")
            if result.get("run_id") not in {None, run_id}:
                raise RuntimeError("VM supervisor returned another run_id")
            result = {**result, "run_id": run_id, "artifacts": self._validate_artifacts(run_id, artifact_dir)}
        except Exception as exc:
            status, error = "failed", str(exc)
        finally:
            _safe_unlink(sample)
            _safe_unlink(sample.parent / "run-spec.json")
            destroyed = False
            try:
                self.config.executor.destroy(run_id)
                destroyed = True
            except Exception as exc:
                status = "failed"
                error = f"{error + '; ' if error else ''}destruction failed: {exc}"
                self._quarantine(run_id, str(exc))
            self.store.update(run_id, status, result=result, error=error, destroyed=destroyed)
            self.store.audit(run_id, "run_finished", {"status": status, "destroyed": destroyed, "error": error})

    def status(self, run_id: str) -> dict[str, Any]:
        if not RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError("Invalid run_id")
        row = self.store.get(run_id)
        if not row:
            raise KeyError(run_id)
        result = json.loads(row["result_json"]) if row["result_json"] else {}
        return {"run_id": run_id, "status": row["status"], "destroyed": bool(row["destroyed"]),
                "error": row["error"], **result}

    def artifacts(self, run_id: str) -> list[dict[str, str]]:
        row = self.store.get(run_id)
        if not row:
            raise KeyError(run_id)
        if row["status"] not in TERMINAL_STATUSES or not row["destroyed"]:
            raise RuntimeError("Artifacts are unavailable until VM destruction is confirmed")
        artifact_dir = (self.runs_dir / run_id / "artifacts").resolve()
        if artifact_dir.parent.parent != self.runs_dir or not artifact_dir.is_dir():
            raise RuntimeError("Artifact directory is unavailable")
        output, total = [], 0
        for metadata in self._validate_artifacts(run_id, artifact_dir):
            path = artifact_dir / metadata["name"]
            data = path.read_bytes()
            total += len(data)
            if total > self.config.max_artifact_bytes or hashlib.sha256(data).hexdigest() != metadata["sha256"]:
                raise RuntimeError("Artifact integrity validation failed")
            output.append({"name": path.name, "sha256": metadata["sha256"],
                           "content_base64": base64.b64encode(data).decode("ascii")})
        return output

    def delete(self, run_id: str) -> bool:
        row = self.store.get(run_id)
        if not row:
            raise KeyError(run_id)
        if row["status"] in {"queued", "running"}:
            raise RuntimeError("A running VM cannot be deleted through the artifact cleanup endpoint")
        if not row["destroyed"]:
            try:
                self.config.executor.destroy(run_id)
                self.store.update(run_id, row["status"], destroyed=True)
            except Exception as exc:
                self._quarantine(run_id, str(exc))
                raise RuntimeError("VM destruction could not be confirmed") from exc
        run_dir = (self.runs_dir / run_id).resolve()
        if run_dir.parent == self.runs_dir:
            shutil.rmtree(run_dir, ignore_errors=True)
        self.store.audit(run_id, "run_deleted")
        return True


def create_sandbox_agent_app(config: AgentConfig):
    try:
        from fastapi import FastAPI, Header, HTTPException, Request
        from pydantic import BaseModel, ConfigDict
    except ImportError as exc:
        raise RuntimeError("Install the api extra to run sandbox-agent") from exc

    agent = SandboxAgent(config)
    app = FastAPI(title="VulnToolSuite Sandbox Agent", version=AGENT_VERSION, docs_url=None, redoc_url=None)

    class RunRequest(BaseModel):
        model_config = ConfigDict(extra="forbid")
        name: str
        sha256: str
        content_base64: str
        policy: dict[str, Any]

    def authorize(authorization: str | None) -> None:
        expected = f"Bearer {config.bearer_token}"
        if authorization is None or not hmac.compare_digest(authorization, expected):
            raise HTTPException(401, "Unauthorized")

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        length = request.headers.get("content-length")
        maximum = int(config.max_sample_bytes * 1.5) + 1024 * 1024
        if length and (not length.isdigit() or int(length) > maximum):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/v1/capabilities")
    def capabilities(authorization: str | None = Header(default=None)):
        authorize(authorization)
        return agent.capabilities()

    def create_run(body, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
                   authorization: str | None = Header(default=None)):
        authorize(authorization)
        try:
            return {"run_id": agent.submit(body.model_dump(), idempotency_key or "")}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
    create_run.__annotations__["body"] = RunRequest
    app.post("/v1/runs", status_code=202)(create_run)

    @app.get("/v1/runs/{run_id}")
    def run_status(run_id: str, authorization: str | None = Header(default=None)):
        authorize(authorization)
        try:
            return agent.status(run_id)
        except (ValueError, KeyError) as exc:
            raise HTTPException(404, "Run not found") from exc

    @app.get("/v1/runs/{run_id}/artifacts")
    def run_artifacts(run_id: str, authorization: str | None = Header(default=None)):
        authorize(authorization)
        try:
            return {"run_id": run_id, "artifacts": agent.artifacts(run_id)}
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.delete("/v1/runs/{run_id}")
    def delete_run(run_id: str, authorization: str | None = Header(default=None)):
        authorize(authorization)
        try:
            return {"run_id": run_id, "destroyed": agent.delete(run_id)}
        except KeyError as exc:
            raise HTTPException(404, "Run not found") from exc
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc

    app.state.sandbox_agent = agent
    return app


def _secret_from_env(name: Any, label: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError(f"{label}_env must name an environment variable")
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Required secret environment variable {name} is not set")
    return value


def load_agent_config(path: str | Path, *, require_acceptance: bool = True) -> AgentConfig:
    """Load deployment configuration without allowing secrets in the JSON file."""
    config_path = Path(path).resolve(strict=True)
    raw = json.loads(config_path.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError("Agent configuration must be an object")
    allowed = {
        "backend_id", "state_dir", "bearer_token_env", "attestation_key_env", "executor",
        "acceptance_file", "max_sample_bytes", "max_artifact_bytes", "retention_seconds", "workers",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"Unknown agent configuration keys: {sorted(unknown)}")
    state_dir = Path(raw.get("state_dir", "")).resolve()
    executor_raw = raw.get("executor")
    if not isinstance(executor_raw, dict):
        raise ValueError("executor configuration is required")
    executor_type = executor_raw.get("type")
    if executor_type == "no-execution":
        executor: VMExecutor = NoExecutionExecutor()
    elif executor_type == "supervisor":
        expected = {
            "type", "path", "sha256", "image_path", "image_sha256", "kernel_path", "kernel_sha256",
        }
        if set(executor_raw) != expected:
            raise ValueError("Supervisor executor must provide exactly the documented pinned paths and digests")
        executor = SupervisorExecutor(
            Path(executor_raw["path"]), executor_raw["sha256"],
            Path(executor_raw["image_path"]), executor_raw["image_sha256"],
            Path(executor_raw["kernel_path"]), executor_raw["kernel_sha256"], state_dir,
        )
    else:
        raise ValueError("executor.type must be supervisor or no-execution")
    attestation_key = _secret_from_env(raw.get("attestation_key_env"), "attestation_key").encode("utf-8")
    acceptance_tests: dict[str, bool] = {}
    acceptance_expires_at = None
    acceptance_path_value = raw.get("acceptance_file")
    acceptance_path = Path(acceptance_path_value).resolve() if acceptance_path_value else None
    if acceptance_path is not None and acceptance_path.exists():
        record = json.loads(acceptance_path.read_text(encoding="utf-8-sig"))
        signature = record.pop("signature", None) if isinstance(record, dict) else None
        expected_signature = hmac.new(attestation_key, _canonical_json(record), hashlib.sha256).hexdigest() if isinstance(record, dict) else ""
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Acceptance record signature is invalid")
        if record.get("executor_identity") != executor.identity():
            raise ValueError("Acceptance record does not match the pinned executor, image, and kernel")
        tested_at = record.get("tested_at")
        if type(tested_at) is not int or time.time() - tested_at > 30 * 24 * 60 * 60 or tested_at > time.time() + 60:
            raise ValueError("Acceptance record is stale or has an invalid timestamp")
        tests = record.get("acceptance_tests")
        if not isinstance(tests, dict):
            raise ValueError("Acceptance record omitted acceptance_tests")
        acceptance_tests = {name: tests.get(name) is True for name in REQUIRED_ACCEPTANCE_TESTS}
        acceptance_expires_at = tested_at + 30 * 24 * 60 * 60
    elif require_acceptance and executor.production_ready:
        raise ValueError("A signed acceptance_file is required for a production executor")
    config = AgentConfig(
        backend_id=raw.get("backend_id", ""), state_dir=state_dir,
        bearer_token=_secret_from_env(raw.get("bearer_token_env"), "bearer_token"),
        attestation_key=attestation_key, executor=executor, acceptance_tests=acceptance_tests,
        max_sample_bytes=raw.get("max_sample_bytes", 4 * 1024 * 1024),
        max_artifact_bytes=raw.get("max_artifact_bytes", 16 * 1024 * 1024),
        retention_seconds=raw.get("retention_seconds", 24 * 60 * 60), workers=raw.get("workers", 2),
        acceptance_expires_at=acceptance_expires_at,
    )
    config.validate()
    return config


def write_acceptance_record(config: AgentConfig, output: str | Path) -> dict[str, Any]:
    """Run supervisor-owned harmless isolation checks and sign their result."""
    if not config.executor.production_ready:
        raise RuntimeError("Acceptance cannot certify the no-execution development executor")
    tests = config.executor.acceptance()
    record = {
        "schema": "vulntools/sandbox-acceptance/v1", "tested_at": int(time.time()),
        "executor_identity": config.executor.identity(),
        "acceptance_tests": {name: tests.get(name) is True for name in sorted(REQUIRED_ACCEPTANCE_TESTS)},
    }
    signed = {**record, "signature": hmac.new(
        config.attestation_key, _canonical_json(record), hashlib.sha256).hexdigest()}
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return signed
