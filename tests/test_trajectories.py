import json
from copy import deepcopy

import pytest

from vulntools.cli import main
from vulntools.closure import run_simple_closure
from vulntools.demo import demo_sources
from vulntools.embedding import HashEncoder, index_records
from vulntools.processing import process
from vulntools.reproduction import smoke_workflow
from vulntools.storage import Store
from vulntools.trajectories import (
    export_category_databases, export_trajectories, trajectory_from_smoke, validate_trajectory,
)


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
        assert summary["docker_lab_executions"] == summary["attested_vm_executions"] == 0
        assert store.trajectory(trajectory["task_id"])["outcome_scope"] == "workflow_canary_only"
        exported = export_trajectories(store, tmp_path / "dataset")
    assert exported["counts"] == {"trajectories": 1, "sft": 1}
    assert exported["contains_internal_reasoning"] is False
    assert exported["docker_lab_executions"] == exported["attested_vm_executions"] == 0
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


def test_category_database_export_is_isolated_and_validated(tmp_path):
    database = tmp_path / "source.sqlite"
    methods = {
        "technical_vulnerability": (
            "xss", "sql_injection", "command_injection", "ssrf", "csrf",
        ),
        "business_logic": (
            "parameter_tampering", "mass_assignment", "authorization_replay",
            "duplicate_submission", "workflow_order_bypass",
        ),
    }
    obstacles = ("none", "session_expired", "field_alias", "input_filter", "state_version")
    phases = (
        "define_scope", "form_hypothesis", "assess_obstacle", "recover_or_proceed",
        "execute_canary", "verify_evidence", "complete_task",
    )
    with Store(database) as store:
        for category, category_methods in methods.items():
            base = trajectory_from_smoke(smoke_workflow(tmp_path / category, mode="fixture"))
            for method in category_methods:
                for obstacle in obstacles:
                    trajectory = deepcopy(base)
                    trajectory["task_id"] = f"docker-lab:{method}:{obstacle}"
                    trajectory["category"] = category
                    trajectory["vulnerability_type"] = method
                    trajectory["environment"]["kind"] = "docker_canary_lab"
                    trajectory["is_simulated"] = False
                    trajectory["execution_ready"] = True
                    trajectory["synthetic_scenario"] = True
                    trajectory["real_vulnerability_verified"] = False
                    trajectory["contains_internal_reasoning"] = False
                    trajectory["chain_complete"] = True
                    trajectory["obstacle_condition"] = {
                        "code": obstacle,
                        "assessment_zh": "已识别阻碍",
                        "strategy_zh": "在原授权范围内恢复",
                        "recovery_verified": True,
                    }
                    trajectory["structured_pentest_chain"] = {
                        "complete": True,
                        "method_profile": {"name_zh": method},
                    }
                    trajectory["completion"] = {"task_completed": True}
                    trajectory["steps"] = [
                        {**deepcopy(base["steps"][0]), "action_type": phase}
                        for phase in phases
                    ]
                    store.save_trajectory(validate_trajectory(trajectory))
        report = export_category_databases(
            store, tmp_path / "split", expected_per_category=25, minimum_required=25
        )
        replaced = export_category_databases(
            store, tmp_path / "split", expected_per_category=25,
            minimum_required=25, overwrite=True,
        )

    assert report["counts"] == {
        "technical_vulnerability": 25,
        "business_logic": 25,
    }
    for category, details in report["databases"].items():
        assert details["quick_check"] == "ok"
        assert details["foreign_key_violations"] == 0
        with Store(details["path"]) as split_store:
            assert split_store.trajectory_summary()["categories"] == {category: 25}
            assert split_store.db.execute(
                "SELECT count(*) FROM structured_pentest_chains"
            ).fetchone()[0] == 25
            assert json.loads(split_store.db.execute(
                "SELECT value FROM dataset_metadata WHERE key='acceptance_checks'"
            ).fetchone()[0])["all_tasks_succeeded"] is True
    assert replaced["counts"] == report["counts"]
