import json

import pytest

from vulntools.cli import main
from vulntools.closure import run_simple_closure
from vulntools.demo import demo_sources
from vulntools.embedding import HashEncoder, index_records
from vulntools.processing import process
from vulntools.reproduction import smoke_workflow
from vulntools.storage import Store
from vulntools.trajectories import export_trajectories, trajectory_from_smoke, validate_trajectory


def test_fixture_workflow_persists_with_honest_execution_boundary(tmp_path):
    report = smoke_workflow(tmp_path / "runs", mode="fixture")
    trajectory = trajectory_from_smoke(report)
    assert trajectory["success"] is True
    assert trajectory["is_simulated"] is True
    assert trajectory["execution_ready"] is False
    assert trajectory["real_vulnerability_verified"] is False
    assert len(trajectory["steps"]) == 3
    assert trajectory["runtime_events"]

    database = tmp_path / "trajectory.sqlite"
    with Store(database) as store:
        assert [row[0] for row in store.db.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )] == [1, 2]
        saved = store.save_trajectory(trajectory)
        assert saved["steps"] == 3
        summary = store.trajectory_summary()
        assert summary["total"] == summary["succeeded"] == summary["simulated"] == 1
        assert summary["real_executions"] == 0
        assert store.trajectory(trajectory["task_id"])["outcome_scope"] == "workflow_canary_only"
        exported = export_trajectories(store, tmp_path / "dataset")
    assert exported["counts"] == {"trajectories": 1, "sft": 1}
    assert exported["contains_internal_reasoning"] is False
    sft = json.loads((tmp_path / "dataset" / "trajectory_sft.jsonl").read_text(encoding="utf-8"))
    assert sft["metadata"]["task_id"] == trajectory["task_id"]


def test_trajectory_validation_rejects_unauthorized_or_internal_reasoning(tmp_path):
    trajectory = trajectory_from_smoke(smoke_workflow(tmp_path, mode="fixture"))
    trajectory["environment"]["authorized"] = False
    with pytest.raises(ValueError, match="authorized"):
        validate_trajectory(trajectory)
    trajectory["environment"]["authorized"] = True
    trajectory["chain_of_thought"] = "must not be stored"
    with pytest.raises(ValueError, match="reasoning"):
        validate_trajectory(trajectory)


def test_trajectory_cli_builds_simple_fixture_closure(tmp_path, capsys):
    database = tmp_path / "cli.sqlite"
    output = tmp_path / "trajectory-output"
    assert main(["--db", str(database), "trajectory-smoke", "--output", str(output)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["workflow_status"] == "fixture_passed"
    assert report["is_simulated"] is True
    assert report["dataset"]["counts"]["trajectories"] == 1
    assert main(["--db", str(database), "trajectory-status"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["total"] == status["simulated"] == 1


def test_one_command_simple_closure_is_usable_and_honest(tmp_path):
    database = tmp_path / "closure.sqlite"
    with Store(database) as store:
        store.save_sources(demo_sources())
        store.replace_canonical(process(store.sources()))
        index_records(store, HashEncoder())
        report = run_simple_closure(
            store, database, tmp_path / "closure", HashEncoder(),
            query="CVE-2099-1001 archive path", expected_id="CVE-2099-1001",
        )
    assert report["status"] == "passed"
    assert all(report["checks"].values())
    assert report["retrieval"]["top_hits"][0]["vuln_id"] == "CVE-2099-1001"
    assert report["production_boundaries"]["full_production_closure"] is False
    assert report["production_boundaries"]["docker_or_vm_execution"] is False
    assert (tmp_path / "closure" / "closure-report.json").is_file()
