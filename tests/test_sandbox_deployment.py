import base64
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
import zipfile

import pytest

from vulntools.cli import main
from vulntools.guest_channel import decode_guest_response, receive_frame, send_frame
from vulntools.guest_monitor import canary_guest_request, guest_guard, normalize_trace, run_guest_canary, validate_guest_request
from vulntools.sandbox import SandboxPolicy, preflight
from vulntools.sandbox_deployment import build_node_bundle, node_check
from tests.test_sandbox_agent import make_agent, request_body


class MemoryConnection:
    def __init__(self, data=b""):
        self.data = bytearray(data)

    def sendall(self, data):
        self.data.extend(data)

    def recv(self, count):
        block = bytes(self.data[:min(count, 3)])  # Partial reads are normal.
        del self.data[:len(block)]
        return block


def _request():
    source = Path(__file__).resolve().parent.parent / "vulntools/canaries/authz_missing.py"
    content = source.read_bytes().replace(b"__PROBE_NONCE__", b"1" * 32)
    return canary_guest_request(content, "run_" + "2" * 32, SandboxPolicy())


def _response(request):
    runtime = {"run_id": request["run_id"], "sample_sha256": request["sample_sha256"], "exit_code": 0, "status": "succeeded"}
    event = {"run_id": request["run_id"], "timestamp": "now", "type": "syscall", "pid": 10, "name": "write"}
    artifacts = {"result.json": json.dumps(runtime).encode(), "events.jsonl": (json.dumps(event) + "\n").encode(),
                 "stdout.txt": b"canary output", "stderr.txt": b""}
    return {"schema": "vulntools/guest-response/v1", **runtime,
            "artifacts": [{"name": name, "content_base64": base64.b64encode(data).decode(),
                           "sha256": hashlib.sha256(data).hexdigest()} for name, data in artifacts.items()]}


def test_guest_frames_handle_partial_reads():
    connection = MemoryConnection()
    send_frame(connection, {"value": "中文", "nested": {"ok": True}})
    assert receive_frame(connection) == {"value": "中文", "nested": {"ok": True}}


@pytest.mark.parametrize("body", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]'])
def test_guest_frames_reject_ambiguous_json(body):
    with pytest.raises(ValueError):
        receive_frame(MemoryConnection(struct.pack("!I", len(body)) + body))


def test_guest_frames_reject_length_and_truncation():
    with pytest.raises(ValueError, match="limit"):
        receive_frame(MemoryConnection(struct.pack("!I", 99999)), maximum=100)
    with pytest.raises(ValueError, match="Truncated"):
        receive_frame(MemoryConnection(struct.pack("!I", 5) + b"{}"))
    with pytest.raises(ValueError, match="limit"):
        send_frame(MemoryConnection(), {"long": "a" * 100}, maximum=10)


def test_guest_only_accepts_exact_canary():
    request = _request()
    content, policy = validate_guest_request(request)
    assert policy.network == "disabled"
    assert hashlib.sha256(content).hexdigest() == request["sample_sha256"]
    changed = content + b"\n# Arbitrary change\n"
    request.update(content_base64=base64.b64encode(changed).decode(), sample_sha256=hashlib.sha256(changed).hexdigest())
    with pytest.raises(ValueError, match="built-in"):
        validate_guest_request(request)


@pytest.mark.parametrize("field,value", [("kind", "real_poc"), ("nonce", "stale"),
                                       ("run_id", "../../escape"), ("variant", "custom")])
def test_guest_request_rejects_unsupported_workloads(field, value):
    request = _request()
    request[field] = value
    with pytest.raises(ValueError):
        validate_guest_request(request)


def test_host_execution_guard_is_not_bypassable_by_request(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    def forbidden(*args, **kwargs):
        raise AssertionError("Process creation must never occur")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    with pytest.raises(RuntimeError, match="host execution forbidden"):
        run_guest_canary(_request())
    with pytest.raises(RuntimeError):
        guest_guard()


def test_syscall_normalization_retains_binding_and_abnormalities():
    events = normalize_trace('1720000000.100001 read(3, "abc", 3) = 3\n'
                             '1720000000.100002 openat(1, "/no", 0) = -1 ENOENT (missing)\n'
                             '1720000000.100003 --- SIGTERM {si_signo=SIGTERM} ---\n', run_id="run_fixture", pid=12)
    assert [event["type"] for event in events] == ["syscall", "syscall", "signal"]
    assert events[1]["return_code"] == -1
    assert all(event["run_id"] == "run_fixture" and event["pid"] == 12 for event in events)
    with pytest.raises(ValueError, match="Unsupported"):
        normalize_trace("1720000000.1 read(3, <unfinished ...>\n", run_id="run_fixture", pid=12)


def test_guest_response_hashes_and_run_binding():
    request = _request()
    response = _response(request)
    artifacts = decode_guest_response(response, run_id=request["run_id"], sample_sha256=request["sample_sha256"])
    assert set(artifacts) == {"result.json", "events.jsonl", "stdout.txt", "stderr.txt"}
    response["artifacts"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest"):
        decode_guest_response(response, run_id=request["run_id"], sample_sha256=request["sample_sha256"])


def test_guest_response_rejects_cross_run_and_paths():
    request = _request()
    response = _response(request)
    with pytest.raises(ValueError, match="bound"):
        decode_guest_response(response, run_id="run_other", sample_sha256=request["sample_sha256"])
    response["artifacts"][0]["name"] = "../../escape"
    with pytest.raises(ValueError, match="Unexpected"):
        decode_guest_response(response, run_id=request["run_id"], sample_sha256=request["sample_sha256"])


def test_read_only_node_check_no_execution_and_no_secret_output(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("TEST_NODE_TOKEN", "secret-value-never-printed" * 2)
    monkeypatch.setenv("TEST_NODE_KEY", "private-key-never-printed" * 2)
    config = tmp_path / "node.json"
    config.write_text(json.dumps({"backend_id": "node", "state_dir": str(tmp_path / "state-not-created"),
                                  "bearer_token_env": "TEST_NODE_TOKEN", "attestation_key_env": "TEST_NODE_KEY",
                                  "executor": {"type": "no-execution"}}))
    report = node_check(config, dedicated_node=True)
    assert report["mechanical_checks_passed"] is False
    assert report["execution_ready"] is False
    assert "secret-value" not in json.dumps(report)
    assert "private-key" not in json.dumps(report)
    assert not (tmp_path / "state-not-created").exists()


def test_offline_bundle_inventory_and_no_database_or_credentials(tmp_path):
    bundle = build_node_bundle(tmp_path)
    with zipfile.ZipFile(bundle["archive"]["path"]) as archive:
        names = archive.namelist()
        assert "deployment/install-sandbox-node.sh" in names
        assert "code/vulntools/guest_monitor.py" in names
        assert all(not name.endswith((".sqlite", ".pem", ".env")) for name in names)
        for name, expected in bundle["files"].items():
            data = archive.read(name)
            assert len(data) == expected["bytes"]
            assert hashlib.sha256(data).hexdigest() == expected["sha256"]
    assert bundle["node_installed"] is False
    assert bundle["execution_ready"] is False


def test_runtime_expired_acceptance_blocks_new_runs(tmp_path):
    agent, _ = make_agent(tmp_path)
    agent.config = replace(agent.config, acceptance_expires_at=int(time.time()) - 1)
    try:
        assert agent.capabilities()["execution_ready"] is False
        with pytest.raises(RuntimeError, match="passing"):
            agent.submit(request_body(), "e" * 32)
    finally:
        agent.pool.shutdown(wait=True)


def test_attestation_lifetime_never_outlives_acceptance(tmp_path):
    agent, _ = make_agent(tmp_path)
    cutoff = int(time.time()) + 60
    agent.config = replace(agent.config, acceptance_expires_at=cutoff)
    try:
        capability = agent.capabilities()
        assert capability["execution_ready"] is True
        assert capability["attestation"]["expires_at"] <= cutoff
    finally:
        agent.pool.shutdown(wait=True)


def test_quarantine_rejected_by_controller_preflight(tmp_path):
    agent, _ = make_agent(tmp_path)
    capabilities = agent.capabilities()
    capabilities["quarantined"] = True
    try:
        assert preflight(SandboxPolicy(), capabilities)["execution_ready"] is False
    finally:
        agent.pool.shutdown(wait=True)


@pytest.mark.parametrize("field,value", [("workers", True), ("max_artifact_bytes", -1), ("retention_seconds", 0)])
def test_agent_config_resource_values_are_strict(tmp_path, field, value):
    agent, _ = make_agent(tmp_path)
    try:
        with pytest.raises(ValueError, match=field):
            replace(agent.config, **{field: value}).validate()
    finally:
        agent.pool.shutdown(wait=True)


def test_node_cli_blocked_exit_and_guest_host_guard(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert main(["sandbox-node-check", "--output", str(tmp_path / "check.json")]) == 2
    assert json.loads(capsys.readouterr().out)["node_started"] is False
    assert main(["sandbox-guest-monitor"]) == 2
    assert "host execution forbidden" in capsys.readouterr().err
