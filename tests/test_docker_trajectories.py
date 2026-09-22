from hashlib import sha256

from vulntools.docker_trajectories import build_docker_scenarios, docker_result_to_trajectory
from vulntools.models import canonical_json


def test_docker_scenarios_are_balanced_unique_and_deterministic():
    first = build_docker_scenarios(1500, "test-seed")
    second = build_docker_scenarios(1500, "test-seed")
    assert first == second
    assert len({item["scenario_id"] for item in first}) == 1500
    counts = {}
    for item in first:
        counts[item["vulnerability_type"]] = counts.get(item["vulnerability_type"], 0) + 1
        assert item["authorized"] is True
        assert item["target_scope"] == "in-container synthetic canary only"
    assert set(counts.values()) == {150}


def test_docker_result_becomes_evidence_bound_non_simulated_canary(tmp_path):
    scenario = build_docker_scenarios(10, "test-seed")[0]
    scenario_sha = sha256(canonical_json(scenario).encode("utf-8")).hexdigest()
    result_path = tmp_path / "container-results.jsonl"
    result_path.write_text("{}\n", encoding="utf-8")
    result = {
        "scenario_id": scenario["scenario_id"],
        "scenario_sha256": scenario_sha,
        "vulnerability_type": scenario["vulnerability_type"],
        "category": scenario["category"],
        "case_index": scenario["case_index"],
        "variant": scenario["variant"],
        "obstacle": scenario["obstacle"],
        "blocked_initial": False,
        "recovered": False,
        "success": True,
        "observation": "The harmless canary produced the expected observable result.",
        "proof": {"canary_seen": True},
        "evidence_digest": scenario["expected_digest"],
        "expected_digest": scenario["expected_digest"],
        "started_at": "2026-09-22T00:00:00+00:00",
        "completed_at": "2026-09-22T00:00:01+00:00",
        "runtime": {
            "container": True,
            "network_expected": "none",
            "interfaces": ["lo"],
            "uid": 65534,
            "gid": 65534,
            "cap_eff": "0000000000000000",
            "no_new_privileges": True,
            "root_write_blocked": True,
            "root_write_errno": 30,
        },
    }
    trajectory = docker_result_to_trajectory(
        scenario,
        result,
        image="python:3.12",
        image_id="sha256:" + "a" * 64,
        restrictions=["network=none", "cap_drop=ALL"],
        result_path=result_path,
        result_line=1,
        batch_id="docker-batch:test",
    )
    assert trajectory["success"] is True
    assert trajectory["is_simulated"] is False
    assert trajectory["synthetic_scenario"] is True
    assert trajectory["real_vulnerability_verified"] is False
    assert trajectory["contains_internal_reasoning"] is False
    assert trajectory["environment"]["production_isolation_attested"] is False
    assert trajectory["outcome_scope"] == "docker_lab_canary_only"
