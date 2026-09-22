"""Guest-only, canary-only commissioning monitor. Never a host executor.

Real PoCs, arbitrary commands, interpreters and paths are not accepted. The
monitor requires an explicitly provisioned Linux guest boot marker, no NIC,
and root monitor/non-root sample identities. The external supervisor still
owns cgroups, deadlines, cleanup and isolation acceptance.
"""
from __future__ import annotations

import base64
from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from .guest_channel import receive_frame, send_frame
from .sandbox import SandboxPolicy

MAX_SAMPLE_BYTES = 256 * 1024
MAX_STREAM_BYTES = 512 * 1024
MAX_TRACE_BYTES = 2 * 1024 * 1024
MAX_EVENTS = 10000
VARIANTS = {"boundary_missing": "authz_missing.py", "boundary_enforced": "authz_enforced.py"}


def validate_guest_request(request: dict[str, Any]) -> tuple[bytes, SandboxPolicy]:
    required = {"schema", "run_id", "kind", "variant", "nonce", "sample_sha256", "content_base64", "policy"}
    if not isinstance(request, dict) or set(request) != required:
        raise ValueError("Guest request has missing or unknown fields")
    if request["schema"] != "vulntools/guest-request/v1" or request["kind"] != "harmless_canary":
        raise ValueError("Only commissioning canaries are supported")
    if not isinstance(request["run_id"], str) or not re.fullmatch(r"run_[0-9a-f]{32}", request["run_id"]):
        raise ValueError("Invalid guest run_id")
    if not isinstance(request["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["nonce"]):
        raise ValueError("Invalid guest nonce")
    variant = request["variant"]
    if not isinstance(variant, str) or variant not in VARIANTS:
        raise ValueError("Unsupported canary variant")
    if not isinstance(request["content_base64"], str) or len(request["content_base64"]) > MAX_SAMPLE_BYTES * 2:
        raise ValueError("Guest sample exceeds limit")
    try:
        content = base64.b64decode(request["content_base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid guest sample encoding") from exc
    if not 1 <= len(content) <= MAX_SAMPLE_BYTES:
        raise ValueError("Guest sample exceeds limit")
    digest = hashlib.sha256(content).hexdigest()
    if digest != request["sample_sha256"]:
        raise ValueError("Guest sample digest mismatch")
    original = (Path(__file__).parent / "canaries" / VARIANTS[variant]).read_bytes()
    expected = original.replace(b"__PROBE_NONCE__", request["nonce"].encode("ascii"))
    if content != expected:
        raise ValueError("Sample is not the built-in canary; arbitrary execution is forbidden")
    policy_data = request["policy"]
    if not isinstance(policy_data, dict) or set(policy_data) != {item.name for item in fields(SandboxPolicy)}:
        raise ValueError("Guest policy must contain exactly the sandbox policy fields")
    policy = SandboxPolicy(**policy_data)
    if policy.validate():
        raise ValueError("Unsafe guest policy")
    return content, policy


def canary_guest_request(content: bytes, run_id: str, policy: SandboxPolicy) -> dict[str, Any]:
    """Reviewed supervisor helper: identify only exact built-in nonce-bound canaries."""
    match = re.search(rb'PROBE_NONCE = "([0-9a-f]{32})"', content)
    if not match:
        raise ValueError("Not a nonce-bound commissioning canary")
    nonce = match.group(1).decode("ascii")
    for variant, filename in VARIANTS.items():
        original = (Path(__file__).parent / "canaries" / filename).read_bytes()
        if content == original.replace(b"__PROBE_NONCE__", match.group(1)):
            from dataclasses import asdict
            request = {"schema": "vulntools/guest-request/v1", "kind": "harmless_canary", "run_id": run_id,
                       "variant": variant, "nonce": nonce, "sample_sha256": hashlib.sha256(content).hexdigest(),
                       "content_base64": base64.b64encode(content).decode("ascii"), "policy": asdict(policy)}
            validate_guest_request(request)
            return request
    raise ValueError("Arbitrary samples are not enabled in the commissioning guest")


def guest_guard() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("Guest monitor requires a provisioned Linux VM; host execution forbidden")
    if os.geteuid() != 0:
        raise RuntimeError("Trusted guest monitor must run as root, samples must not")
    marker = Path("/etc/vulntools-guest-canary")
    if not marker.is_file() or marker.read_text().strip() != "canary-only-v1":
        raise RuntimeError("Provisioned guest marker is missing; host execution forbidden")
    if marker.stat().st_uid != 0 or marker.stat().st_mode & 0o022:
        raise RuntimeError("Guest marker must be root-owned and not group/other writable")
    if "vulntools_guest=canary" not in Path("/proc/cmdline").read_text().split():
        raise RuntimeError("Explicit guest boot marker missing; host execution forbidden")
    if any(path.name != "lo" for path in Path("/sys/class/net").iterdir()):
        raise RuntimeError("Commissioning guest must have no network interface except loopback")
    for binary in (Path("/usr/bin/python3"), Path("/usr/bin/strace")):
        target = binary.resolve(strict=True)
        stat = target.stat()
        if not target.is_file() or stat.st_uid != 0 or stat.st_mode & 0o022 or not os.access(target, os.X_OK):
            raise RuntimeError("Guest interpreter and tracer must be root-owned and non-writable")


def normalize_trace(text: str, *, run_id: str, pid: int) -> list[dict[str, Any]]:
    """Normalize complete strace records; unsupported lines fail closed."""
    events = []
    for line in text.splitlines():
        match = re.fullmatch(r"(\d+\.\d+) (.+)", line.strip())
        if not match:
            raise ValueError("Unrecognized syscall trace line")
        timestamp, body = match.groups()
        syscall = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\(.*\)\s+=\s+(.+)$", body)
        if syscall:
            returned = re.match(r"(-?\d+)(?:\s|$)", syscall.group(2))
            events.append({"run_id": run_id, "timestamp": timestamp, "type": "syscall", "pid": pid,
                           "name": syscall.group(1), "return_code": int(returned.group(1)) if returned else None,
                           "raw": body})
        elif body.startswith("--- SIG") or body.startswith("+++ killed by"):
            events.append({"run_id": run_id, "timestamp": timestamp, "type": "signal", "pid": pid, "raw": body})
        elif body.startswith("+++ exited with"):
            events.append({"run_id": run_id, "timestamp": timestamp, "type": "exit", "pid": pid, "raw": body})
        else:
            # Unfinished/resumed traces and diagnostics need a richer parser before production PoCs.
            raise ValueError("Unsupported syscall trace; monitoring cannot certify this run")
        if len(events) > MAX_EVENTS:
            raise ValueError("Guest syscall events exceeded limit")
    return events


def run_guest_canary(request: dict[str, Any]) -> dict[str, Any]:
    guest_guard()  # Always before sample or process creation, cannot be disabled by a request.
    content, policy = validate_guest_request(request)
    from datetime import datetime, timezone
    import resource
    run_id, streams, overflow = request["run_id"], {}, threading.Event()
    status, events, code = "failed", [], None
    with tempfile.TemporaryDirectory(prefix="vulntools-canary-", dir="/run") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        trace_dir = root / "trace"
        trace_dir.mkdir(mode=0o700)
        os.chown(trace_dir, 10000, 10000)
        sample = root / "sample.py"
        sample.write_bytes(content)
        sample.chmod(0o444)
        def limits():
            resource.setrlimit(resource.RLIMIT_AS, (policy.memory_mb * 1024 * 1024,) * 2)
            resource.setrlimit(resource.RLIMIT_CPU, (policy.timeout_seconds + 1,) * 2)
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_TRACE_BYTES,) * 2)
            resource.setrlimit(resource.RLIMIT_NPROC, (policy.process_limit,) * 2)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Single-run guest process, not called from a threaded host service.
        process = subprocess.Popen([
            "/usr/bin/strace", "-ff", "-qq", "-ttt", "-s", "128", "-o", str(trace_dir / "trace"),
            "/usr/bin/python3", "-I", "-B", str(sample),
        ], shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(root), env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            user=10000, group=10000, extra_groups=[], start_new_session=True, preexec_fn=limits)
        def collect(name, pipe):
            collected = bytearray()
            try:
                while True:
                    block = pipe.read(65536)
                    if not block:
                        break
                    if len(collected) + len(block) > MAX_STREAM_BYTES:
                        overflow.set()
                        break
                    collected.extend(block)
            finally:
                streams[name] = bytes(collected)
                pipe.close()
        readers = [threading.Thread(target=collect, args=(name, pipe), daemon=True)
                   for name, pipe in (("stdout.txt", process.stdout), ("stderr.txt", process.stderr))]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + policy.timeout_seconds
        while process.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
            time.sleep(0.02)
        timed_out = process.poll() is None and not overflow.is_set()
        # Kill the entire sample/tracer group even after the parent exits.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        code = process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=2)
        status = "policy_violation" if overflow.is_set() else "timed_out" if timed_out else "succeeded" if code == 0 else "failed"
        try:
            total = 0
            for trace in sorted(trace_dir.iterdir()):
                if not trace.is_file() or not re.fullmatch(r"trace\.[0-9]+", trace.name):
                    raise ValueError("Unexpected guest trace artifact")
                total += trace.stat().st_size
                if total > MAX_TRACE_BYTES:
                    raise ValueError("Guest trace exceeded limit")
                events.extend(normalize_trace(trace.read_text(encoding="utf-8"), run_id=run_id,
                                              pid=int(trace.name.rsplit(".", 1)[1])))
                if len(events) > MAX_EVENTS:
                    raise ValueError("Guest syscall events exceeded limit")
            if any(reader.is_alive() for reader in readers) or not any(event["type"] == "syscall" for event in events):
                raise ValueError("Monitor incomplete or missing syscalls")
        except (ValueError, OSError):
            status = "monitor_lost"
        if status != "succeeded":
            events.append({"run_id": run_id, "timestamp": datetime.now(timezone.utc).isoformat(),
                           "type": status if status in {"timed_out", "monitor_lost", "policy_violation"} else "signal"})
            if status == "timed_out":
                events[-1]["type"] = "timeout"
        artifacts = {**streams,
                     "events.jsonl": ("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n").encode(),
                     "result.json": json.dumps({"run_id": run_id, "sample_sha256": request["sample_sha256"],
                                                "exit_code": code, "status": status}).encode()}
    return {"schema": "vulntools/guest-response/v1", "run_id": run_id, "status": status,
            "sample_sha256": request["sample_sha256"], "exit_code": code,
            "artifacts": [{"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                           "content_base64": base64.b64encode(data).decode("ascii")}
                          for name, data in sorted(artifacts.items())]}


def serve_one_guest(port: int = 4050) -> dict[str, Any]:
    guest_guard()
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid guest port")
    if not hasattr(socket, "AF_VSOCK"):
        raise RuntimeError("Guest kernel/Python has no vsock support")
    with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as listener:
        listener.bind((socket.VMADDR_CID_ANY, port))
        listener.listen(1)
        listener.settimeout(60)
        connection, peer = listener.accept()
        with connection:
            if peer[0] != socket.VMADDR_CID_HOST:
                raise RuntimeError("Only host-initiated supervisor requests are accepted")
            connection.settimeout(15)
            response = run_guest_canary(receive_frame(connection))
            send_frame(connection, response)
    return {"status": response["status"], "run_id": response["run_id"], "mode": "guest_canary_only"}
