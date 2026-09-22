import hashlib
import json
from pathlib import Path

import pytest

from vulntools.cli import main
from vulntools.reproduction import PIN_NAMES, _FixtureBackend, candidate_plan, smoke_workflow
from vulntools.sandbox import SandboxPolicy
from vulntools.storage import Store
from tests.test_training_dataset import _poc, _record


def _fixture_with_change(monkeypatch, change):
    class ChangedBackend(_FixtureBackend):
        def artifacts(self, run_id):
            artifacts = super().artifacts(run_id)
            change(artifacts)
            return artifacts
    monkeypatch.setattr("vulntools.reproduction._FixtureBackend", ChangedBackend)


def test_fixture_pair_is_not_real_verification_and_no_host_execution(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("No local execution is allowed")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("subprocess.run", forbidden)
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "fixture_passed"
    assert report["sample_executed"] is False
    assert report["is_simulated"] is True
    assert report["real_vulnerability_verified"] is False
    assert report["database_updated"] is False
    assert len(report["runs"]) == 2
    assert all(item["destroyed"] for item in report["runs"])
    assert report["execution_ready"] is False
    plan = json.loads((Path(report["directory"]) / "plan.json").read_text())
    assert plan["samples"][0]["expected_observation"]["access_allowed"] is True
    assert plan["samples"][1]["expected_observation"]["access_allowed"] is False


def test_default_only_plans_and_each_attempt_is_unique(tmp_path):
    one, two = smoke_workflow(tmp_path), smoke_workflow(tmp_path)
    assert one["status"] == "planned"
    assert not one["runs"]
    assert one["nonce"] != two["nonce"]
    assert one["directory"] != two["directory"]
    assert one["recipe_sha256"] != two["recipe_sha256"]


def test_exit_zero_does_not_prove_effect(tmp_path, monkeypatch):
    def change(artifacts):
        observation = json.loads(artifacts["stdout.txt"])
        observation["access_allowed"] = True
        observation["marker_observed"] = True
        artifacts["stdout.txt"] = json.dumps(observation).encode()
    _fixture_with_change(monkeypatch, change)
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "not_confirmed"
    assert report["runs"][1]["verdict"]["status"] == "failed"


@pytest.mark.parametrize("field,value", [("nonce", "stale"), ("variant", "wrong"),
                                       ("access_allowed", 1)])
def test_wrong_nonce_variant_or_boolean_fails(tmp_path, monkeypatch, field, value):
    def change(artifacts):
        observation = json.loads(artifacts["stdout.txt"])
        observation[field] = value
        artifacts["stdout.txt"] = json.dumps(observation).encode()
    _fixture_with_change(monkeypatch, change)
    assert smoke_workflow(tmp_path, mode="fixture")["status"] == "not_confirmed"


def test_wrong_runtime_binding_fails(tmp_path, monkeypatch):
    def change(artifacts):
        runtime = json.loads(artifacts["result.json"])
        runtime["run_id"] = "another_run"
        artifacts["result.json"] = json.dumps(runtime).encode()
    _fixture_with_change(monkeypatch, change)
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "not_confirmed"
    assert "runtime_evidence_binding_or_exit_mismatch" in report["runs"][0]["verdict"]["issues"]


def test_missing_log_destroys_and_never_publishes_success(tmp_path, monkeypatch):
    _fixture_with_change(monkeypatch, lambda artifacts: artifacts.pop("events.jsonl"))
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "blocked_or_failed"
    assert report["last_submission"]["destruction_confirmed"] is True
    assert not report["runs"]


def test_destroy_failure_is_not_confirmed(tmp_path, monkeypatch):
    class CannotDestroy(_FixtureBackend):
        def destroy(self, run_id):
            raise RuntimeError("VM destruction not confirmed")
    monkeypatch.setattr("vulntools.reproduction._FixtureBackend", CannotDestroy)
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "blocked_or_failed"
    assert report["last_submission"]["destruction_confirmed"] is False
    assert not report["runs"]


def test_empty_syscall_log_not_success(tmp_path, monkeypatch):
    def change(artifacts):
        runtime = json.loads(artifacts["result.json"])
        artifacts["events.jsonl"] = (json.dumps({"run_id": runtime["run_id"], "timestamp": "now",
                                                "type": "heartbeat"}) + "\n").encode()
    _fixture_with_change(monkeypatch, change)
    assert smoke_workflow(tmp_path, mode="fixture")["status"] == "not_confirmed"


def test_vm_cannot_start_without_configuration(tmp_path):
    with pytest.raises(ValueError, match="requires"):
        smoke_workflow(tmp_path, mode="vm")
    report = smoke_workflow(tmp_path, mode="vm", pins={name: "1" * 64 for name in PIN_NAMES})
    assert report["status"] == "blocked"
    assert report["sample_executed"] is False


def test_wrong_environment_pin_refused_before_submission(tmp_path):
    backend = _FixtureBackend("nonce")
    report = smoke_workflow(tmp_path, mode="vm", backend=backend,
                            pins={name: "1" * 64 for name in PIN_NAMES})
    assert report["status"] == "blocked_or_failed"
    assert not backend.runs
    assert any("pin mismatch" in issue for issue in report["issues"])


def test_unsafe_policy_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unsafe"):
        smoke_workflow(tmp_path, mode="fixture", policy=SandboxPolicy(host_mounts=True))


def test_candidate_selection_is_read_only_and_does_not_export_code(tmp_path):
    database = tmp_path / "db.sqlite"
    first, second = "CVE-2026-9000", "CVE-2026-9001"
    linux = _poc(1, first)
    linux["metadata"]["platform"] = "linux"
    rejected = _poc(2, second)
    rejected["review_status"] = "rejected"
    with Store(database) as store:
        store.replace_canonical([_record(first, "Source description of a test record with valid metadata."),
                                 _record(second, "Second source description of another record.")])
        store.save_poc_artifacts([linux, rejected])
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    report = candidate_plan(database)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    assert report["count"] == 1
    assert report["candidates"][0]["vuln_id"] == first
    assert report["code_executed"] is False
    assert "content" not in report["candidates"][0]
    assert report["candidates"][0]["execution_ready"] is False


def test_cli_smoke_and_missing_live_configuration(tmp_path, capsys):
    assert main(["reproduction-smoke", "--mode", "fixture", "--output", str(tmp_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "fixture_passed"
    assert main(["reproduction-smoke", "--mode", "vm", "--output", str(tmp_path)]) == 2
    assert "requires" in capsys.readouterr().err


def test_cli_rejects_vm_parameters_in_fixture_mode(tmp_path, capsys):
    assert main(["reproduction-smoke", "--mode", "fixture", "--output", str(tmp_path),
                 "--backend-url", "https://example.invalid"]) == 2
    assert "must not" in capsys.readouterr().err


def test_monitor_abnormality_cannot_pass(tmp_path, monkeypatch):
    def change(artifacts):
        runtime = json.loads(artifacts["result.json"])
        event = {"run_id": runtime["run_id"], "timestamp": "now", "type": "monitor_lost"}
        artifacts["events.jsonl"] += (json.dumps(event) + "\n").encode()
    _fixture_with_change(monkeypatch, change)
    assert smoke_workflow(tmp_path, mode="fixture")["status"] == "not_confirmed"


def test_missing_output_is_not_effect_evidence(tmp_path, monkeypatch):
    _fixture_with_change(monkeypatch, lambda artifacts: artifacts.pop("stdout.txt"))
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "not_confirmed"
    assert "missing_evidence:stdout.txt" in report["runs"][0]["verdict"]["issues"]


def test_initial_shortlist_excludes_explicit_high_risk(tmp_path):
    database = tmp_path / "db.sqlite"
    cve = "CVE-2026-9000"
    artifact = _poc(1, cve)
    artifact["title"] = "Linux Kernel Information Disclosure"
    with Store(database) as store:
        store.replace_canonical([_record(cve, "A fixture source record describing a vulnerability with sufficient metadata.")])
        store.save_poc_artifacts([artifact])
    assert candidate_plan(database)["count"] == 0


def test_negative_syscall_return_is_diagnostic_not_automatic_failure(tmp_path, monkeypatch):
    def change(artifacts):
        runtime = json.loads(artifacts["result.json"])
        event = {"run_id": runtime["run_id"], "timestamp": "now", "type": "syscall", "name": "openat",
                 "pid": 1, "return_code": -1}
        artifacts["events.jsonl"] += (json.dumps(event) + "\n").encode()
    _fixture_with_change(monkeypatch, change)
    report = smoke_workflow(tmp_path, mode="fixture")
    assert report["status"] == "fixture_passed"
    assert all(item["verdict"]["syscall_error_count"] == 1 for item in report["runs"])
