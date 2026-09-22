import base64
import hashlib
import json
import time

import pytest

from vulntools.sandbox import REQUIRED_ACCEPTANCE_TESTS, SandboxPolicy, validate_attestation, validate_capabilities
from vulntools.sandbox_agent import AgentConfig, NoExecutionExecutor, SandboxAgent, create_sandbox_agent_app


class IsolatedFixtureExecutor:
    production_ready = True

    def __init__(self, fail_destroy=False):
        self.destroyed = []
        self.fail_destroy = fail_destroy

    def identity(self):
        return {
            "supervisor_sha256": "1" * 64,
            "image_sha256": "2" * 64,
            "kernel_sha256": "3" * 64,
        }

    def acceptance(self):
        return {name: True for name in REQUIRED_ACCEPTANCE_TESTS}

    def run(self, run_id, sample, policy, artifact_dir):
        # The fixture only checks transport bytes; it never starts the sample.
        assert sample.read_bytes() == b"harmless fixture\n"
        (artifact_dir / "events.jsonl").write_text(json.dumps({
            "run_id": run_id, "timestamp": "2026-09-17T00:00:00Z",
            "type": "syscall", "name": "read", "pid": 1, "return_code": 1,
        }) + "\n", encoding="utf-8")
        (artifact_dir / "result.json").write_text('{"exit_code":0}\n', encoding="utf-8")
        return {"run_id": run_id, "status": "succeeded", "exit_code": 0}

    def destroy(self, run_id):
        if self.fail_destroy:
            raise RuntimeError("fixture destroy failure")
        self.destroyed.append(run_id)


def make_agent(tmp_path, executor=None):
    executor = executor or IsolatedFixtureExecutor()
    key = b"a" * 32
    config = AgentConfig(
        backend_id="fixture-vm", state_dir=tmp_path / "agent",
        bearer_token="t" * 32, attestation_key=key, executor=executor,
        acceptance_tests={name: True for name in REQUIRED_ACCEPTANCE_TESTS},
    )
    return SandboxAgent(config), key


def wait_terminal(agent, run_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        value = agent.status(run_id)
        if value["status"] not in {"queued", "running"}:
            return value
        time.sleep(0.01)
    raise AssertionError("fixture run did not finish")


def request_body():
    content = b"harmless fixture\n"
    return {
        "name": "fixture.txt", "sha256": hashlib.sha256(content).hexdigest(),
        "content_base64": base64.b64encode(content).decode("ascii"),
        "policy": SandboxPolicy().__dict__,
    }


def test_agent_signed_attestation_run_idempotency_and_artifact_integrity(tmp_path):
    agent, key = make_agent(tmp_path)
    capabilities = agent.capabilities()
    assert capabilities["execution_ready"] is True
    assert validate_attestation(capabilities, key) == []
    assert validate_capabilities(capabilities, key) == []

    idem = "f" * 64
    run_id = agent.submit(request_body(), idem)
    assert agent.submit(request_body(), idem) == run_id
    result = wait_terminal(agent, run_id)
    assert result["status"] == "succeeded" and result["destroyed"] is True
    artifacts = agent.artifacts(run_id)
    assert {item["name"] for item in artifacts} == {"events.jsonl", "result.json"}
    assert not (tmp_path / "agent" / "runs" / run_id / "sample.bin").exists()
    assert agent.delete(run_id) is True
    agent.pool.shutdown(wait=True)


def test_attestation_rejects_tampering_and_expiry(tmp_path):
    agent, key = make_agent(tmp_path)
    capabilities = agent.capabilities()
    capabilities["attestation"]["image_sha256"] = "9" * 64
    assert "signature is invalid" in "; ".join(validate_attestation(capabilities, key))
    fresh = agent.capabilities()
    future = fresh["attestation"]["expires_at"] + 1
    assert "expired" in "; ".join(validate_attestation(fresh, key, now=future))
    agent.pool.shutdown(wait=True)


def test_agent_rejects_idempotency_reuse_for_different_request(tmp_path):
    agent, _ = make_agent(tmp_path)
    body = request_body()
    agent.submit(body, "x" * 32)
    changed = request_body()
    changed["name"] = "another.txt"
    with pytest.raises(ValueError, match="different request"):
        agent.submit(changed, "x" * 32)
    agent.pool.shutdown(wait=True)


def test_agent_quarantines_node_when_destruction_fails(tmp_path):
    agent, _ = make_agent(tmp_path, IsolatedFixtureExecutor(fail_destroy=True))
    run_id = agent.submit(request_body(), "q" * 32)
    result = wait_terminal(agent, run_id)
    assert result["destroyed"] is False
    assert agent.quarantined is True
    with pytest.raises(RuntimeError, match="quarantined"):
        agent.submit(request_body(), "z" * 32)
    agent.pool.shutdown(wait=True)


def test_agent_app_exposes_only_versioned_control_routes(tmp_path):
    agent, _ = make_agent(tmp_path)
    app = create_sandbox_agent_app(agent.config)
    paths = {route.path for route in app.routes}
    assert {"/v1/capabilities", "/v1/runs", "/v1/runs/{run_id}",
            "/v1/runs/{run_id}/artifacts"}.issubset(paths)
    agent.pool.shutdown(wait=True)
    app.state.sandbox_agent.pool.shutdown(wait=True)


def test_agent_http_api_requires_bearer_and_supports_full_lifecycle(tmp_path):
    from fastapi.testclient import TestClient

    executor = IsolatedFixtureExecutor()
    config = AgentConfig(
        backend_id="fixture-api", state_dir=tmp_path / "api-agent",
        bearer_token="t" * 32, attestation_key=b"a" * 32, executor=executor,
        acceptance_tests={name: True for name in REQUIRED_ACCEPTANCE_TESTS},
    )
    app = create_sandbox_agent_app(config)
    headers = {"Authorization": "Bearer " + "t" * 32, "Idempotency-Key": "i" * 32}
    with TestClient(app) as client:
        assert client.get("/v1/capabilities").status_code == 401
        assert client.get("/v1/capabilities", headers=headers).json()["execution_ready"] is True
        response = client.post("/v1/runs", headers=headers, json=request_body())
        assert response.status_code == 202
        run_id = response.json()["run_id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = client.get(f"/v1/runs/{run_id}", headers=headers).json()
            if status["status"] not in {"queued", "running"}:
                break
            time.sleep(0.01)
        assert status["destroyed"] is True
        assert client.get(f"/v1/runs/{run_id}/artifacts", headers=headers).status_code == 200
        assert client.delete(f"/v1/runs/{run_id}", headers=headers).json()["destroyed"] is True
    app.state.sandbox_agent.pool.shutdown(wait=True)


def test_development_executor_can_never_accept_a_sample(tmp_path):
    config = AgentConfig(
        backend_id="disabled-node", state_dir=tmp_path / "disabled",
        bearer_token="t" * 32, attestation_key=b"a" * 32,
        executor=NoExecutionExecutor(),
    )
    agent = SandboxAgent(config)
    assert agent.capabilities()["execution_ready"] is False
    with pytest.raises(RuntimeError, match="no current passing"):
        agent.submit(request_body(), "n" * 32)
    agent.pool.shutdown(wait=True)
