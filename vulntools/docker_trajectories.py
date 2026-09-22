"""Generate evidence-bound structured trajectories in a restricted Docker canary lab."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .models import canonical_json, now
from .storage import Store
from .trajectories import SCHEMA, export_trajectories, import_trajectories, validate_trajectory


SCENARIO_TYPES = (
    ("technical_vulnerability", "xss"),
    ("technical_vulnerability", "sql_injection"),
    ("technical_vulnerability", "command_injection"),
    ("technical_vulnerability", "ssrf"),
    ("technical_vulnerability", "csrf"),
    ("business_logic", "parameter_tampering"),
    ("business_logic", "mass_assignment"),
    ("business_logic", "authorization_replay"),
    ("business_logic", "duplicate_submission"),
    ("business_logic", "workflow_order_bypass"),
)
VARIANTS = ("baseline", "alternate_field", "encoded_input", "new_session", "state_refresh", "replay")
OBSTACLES = ("none", "session_expired", "field_alias", "input_filter", "state_version")
RECOVERY = {
    "session_expired": "Refresh the disposable lab session and repeat the same canary-bound check.",
    "field_alias": "Resolve the field from the lab schema, then repeat without widening the target scope.",
    "input_filter": "Use the lab's documented canonical encoding and repeat the harmless canary.",
    "state_version": "Reload the disposable scenario state and repeat against the current version.",
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_docker_scenarios(count: int = 1500, seed: str = "vulntools-docker-lab-v1") -> list[dict[str, Any]]:
    if type(count) is not int or count < len(SCENARIO_TYPES):
        raise ValueError(f"count must be an integer of at least {len(SCENARIO_TYPES)}")
    if not isinstance(seed, str) or not seed.strip():
        raise ValueError("seed must be nonempty")
    scenarios: list[dict[str, Any]] = []
    per_type = Counter()
    for ordinal in range(count):
        category, vulnerability_type = SCENARIO_TYPES[ordinal % len(SCENARIO_TYPES)]
        case_index = per_type[vulnerability_type]
        per_type[vulnerability_type] += 1
        canary = hashlib.sha256(f"{seed}:{vulnerability_type}:{case_index}".encode("utf-8")).hexdigest()[:24]
        scenario_id = f"docker-lab:{vulnerability_type}:{case_index:04d}:{canary[:8]}"
        obstacle = OBSTACLES[(case_index // len(VARIANTS)) % len(OBSTACLES)]
        expected_digest = hashlib.sha256(
            f"{scenario_id}|{vulnerability_type}|{canary}|passed".encode("utf-8")
        ).hexdigest()
        scenarios.append({
            "schema": "vulntools/docker-trajectory-scenario/v1",
            "scenario_id": scenario_id,
            "category": category,
            "vulnerability_type": vulnerability_type,
            "case_index": case_index,
            "variant": VARIANTS[case_index % len(VARIANTS)],
            "obstacle": obstacle,
            "canary": canary,
            "expected_digest": expected_digest,
            "authorized": True,
            "target_scope": "in-container synthetic canary only",
        })
    return scenarios


def _docker_image_id(docker: str, image: str) -> str:
    result = subprocess.run(
        [docker, "image", "inspect", image, "--format", "{{.Id}}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    image_id = result.stdout.strip()
    if result.returncode != 0 or not image_id.startswith("sha256:"):
        raise RuntimeError(
            f"Docker image {image!r} must already exist locally; automatic pulls are disabled"
        )
    return image_id


def _run_restricted_container(
    scenarios_text: str,
    *,
    image: str,
    runner_path: Path,
    timeout: int,
) -> tuple[str, str, str, list[str]]:
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("docker executable was not found")
    image_id = _docker_image_id(docker, image)
    runner_source = runner_path.read_text(encoding="utf-8")
    command = [
        docker,
        "run",
        "--rm",
        "--interactive",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=64",
        "--memory=256m",
        "--cpus=1.0",
        "--user=65534:65534",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=32m",
        "--hostname=vulntools-lab",
        "--env=PYTHONHASHSEED=0",
        "--label=vulntools.scope=harmless-canary",
        image,
        "python",
        "-B",
        "-c",
        runner_source,
    ]
    result = subprocess.run(
        command,
        input=scenarios_text,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    if result.returncode != 0:
        message = result.stderr.strip()[-2000:]
        raise RuntimeError(f"Restricted Docker canary batch failed with exit {result.returncode}: {message}")
    restrictions = [
        "network=none",
        "read_only_root=true",
        "cap_drop=ALL",
        "no_new_privileges=true",
        "pids_limit=64",
        "memory=256m",
        "cpus=1.0",
        "uid=65534",
        "tmpfs_noexec=true",
        "pull=never",
    ]
    return result.stdout, result.stderr, image_id, restrictions


def _step(
    observation: str,
    action_type: str,
    tool: str,
    input_value: dict[str, Any],
    result: dict[str, Any],
    *,
    blocked: bool = False,
    recovery_strategy: str | None = None,
    evidence: list[str] | None = None,
    decision_basis: str,
) -> dict[str, Any]:
    return {
        "observation": observation,
        "action_type": action_type,
        "tool": tool,
        "input": input_value,
        "result": result,
        "blocked": blocked,
        "recovery_strategy": recovery_strategy,
        "evidence": evidence or [],
        "decision_basis": decision_basis,
    }


def docker_result_to_trajectory(
    scenario: dict[str, Any],
    result: dict[str, Any],
    *,
    image: str,
    image_id: str,
    restrictions: list[str],
    result_path: Path,
    result_line: int,
    batch_id: str,
) -> dict[str, Any]:
    if result.get("scenario_id") != scenario["scenario_id"]:
        raise ValueError("Docker result identity does not match its scenario")
    if result.get("scenario_sha256") != _sha256_bytes(canonical_json(scenario).encode("utf-8")):
        raise ValueError(f"Scenario hash mismatch for {scenario['scenario_id']}")
    if result.get("evidence_digest") != scenario["expected_digest"]:
        raise ValueError(f"Evidence digest mismatch for {scenario['scenario_id']}")
    if result.get("success") is not True:
        raise ValueError(f"Docker canary did not succeed for {scenario['scenario_id']}")
    runtime = result.get("runtime") or {}
    if runtime.get("container") is not True or runtime.get("network_expected") != "none":
        raise ValueError(f"Docker runtime evidence is incomplete for {scenario['scenario_id']}")
    if runtime.get("uid") != 65534 or runtime.get("gid") != 65534:
        raise ValueError(f"Docker canary did not run as the expected unprivileged identity for {scenario['scenario_id']}")
    if runtime.get("cap_eff") != "0000000000000000" or runtime.get("no_new_privileges") is not True:
        raise ValueError(f"Docker privilege restrictions were not observed for {scenario['scenario_id']}")
    if runtime.get("interfaces") != ["lo"] or runtime.get("root_write_blocked") is not True:
        raise ValueError(f"Docker network/read-only restrictions were not observed for {scenario['scenario_id']}")

    evidence_pointer = f"{result_path.resolve()}#L{result_line}"
    steps = [
        _step(
            "A deterministic authorized scenario and unique canary were prepared for the local Docker lab.",
            "prepare",
            "vulntools.docker_trajectory_lab",
            {
                "scenario_id": scenario["scenario_id"],
                "variant": scenario["variant"],
                "canary_sha256": _sha256_bytes(scenario["canary"].encode("utf-8")),
            },
            {"status": "accepted", "scenario_sha256": result["scenario_sha256"]},
            evidence=[evidence_pointer],
            decision_basis="The manifest explicitly authorizes only a synthetic in-container canary.",
        )
    ]
    if result.get("blocked_initial"):
        obstacle = str(result["obstacle"])
        recovery = RECOVERY[obstacle]
        steps.append(
            _step(
                f"The initial lab attempt encountered the declared {obstacle} obstacle.",
                "recover",
                "docker_canary_state_machine",
                {"obstacle": obstacle},
                {"status": "recovered", "recovered": result.get("recovered") is True},
                blocked=True,
                recovery_strategy=recovery,
                evidence=[evidence_pointer],
                decision_basis="The obstacle is declared by the scenario and recovery remains inside the same disposable scope.",
            )
        )
    steps.append(
        _step(
            str(result["observation"]),
            "execute_canary",
            "restricted_docker_container",
            {
                "vulnerability_type": scenario["vulnerability_type"],
                "variant": scenario["variant"],
                "payload_disclosed": False,
            },
            {"status": "passed", "proof": result["proof"]},
            evidence=[evidence_pointer],
            decision_basis="The canary-specific control comparison produced an observable difference inside the isolated lab.",
        )
    )
    steps[-1]["result"]["runtime_evidence"] = runtime
    steps.append(
        _step(
            "The result digest was compared with the host-generated expected digest.",
            "verify",
            "sha256_oracle",
            {"expected_digest": scenario["expected_digest"]},
            {"actual_digest": result["evidence_digest"], "matched": True},
            evidence=[evidence_pointer],
            decision_basis="Matching independent scenario and evidence digests is the completion oracle for this canary task.",
        )
    )

    events = [{
        "run_id": scenario["scenario_id"],
        "timestamp": result["started_at"],
        "type": "container_scenario_started",
        "batch_id": batch_id,
        "image_id": image_id,
    }]
    if result.get("blocked_initial"):
        events.append({
            "run_id": scenario["scenario_id"],
            "timestamp": result["started_at"],
            "type": "declared_obstacle_recovered",
            "obstacle": result["obstacle"],
        })
    events.append({
        "run_id": scenario["scenario_id"],
        "timestamp": result["completed_at"],
        "type": "canary_verified",
        "evidence_digest": result["evidence_digest"],
    })

    trajectory = {
        "schema_version": SCHEMA,
        "task_id": scenario["scenario_id"],
        "category": scenario["category"],
        "vulnerability_type": scenario["vulnerability_type"],
        "environment": {
            "kind": "docker_canary_lab",
            "authorized": True,
            "scope": "local synthetic canary only; no public or third-party target",
            "image": image,
            "image_id": image_id,
            "batch_id": batch_id,
            "restrictions": restrictions,
            "production_isolation_attested": False,
        },
        "precondition": "Docker daemon is local and available; image exists locally; the run is network-disabled and limited to built-in harmless canaries.",
        "steps": steps,
        "success": True,
        "blocked": False,
        "recovery_strategy": RECOVERY.get(str(result.get("obstacle"))),
        "evidence": [{
            "path": str(result_path.resolve()),
            "line": result_line,
            "scenario_sha256": result["scenario_sha256"],
            "evidence_digest": result["evidence_digest"],
        }],
        "runtime_events": events,
        "created_at": result["started_at"],
        "completed_at": result["completed_at"],
        "is_simulated": False,
        "execution_ready": True,
        "real_vulnerability_verified": False,
        "synthetic_scenario": True,
        "outcome_scope": "docker_lab_canary_only",
        "contains_internal_reasoning": False,
    }
    return validate_trajectory(trajectory)


def generate_docker_trajectories(
    store: Store,
    output: str | Path,
    *,
    count: int = 1500,
    seed: str = "vulntools-docker-lab-v1",
    image: str = "python:3.12",
    timeout: int = 300,
) -> dict[str, Any]:
    if type(timeout) is not int or timeout < 10:
        raise ValueError("timeout must be an integer of at least 10 seconds")
    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    runner_path = Path(__file__).resolve().parents[1] / "deployment" / "docker_trajectory_lab.py"
    if not runner_path.is_file():
        raise RuntimeError(f"Docker trajectory runner is missing: {runner_path}")

    scenarios = build_docker_scenarios(count, seed)
    scenarios_text = "".join(canonical_json(item) + "\n" for item in scenarios)
    scenario_path = directory / "scenario-input.jsonl"
    result_path = directory / "container-results.jsonl"
    stderr_path = directory / "container-stderr.txt"
    trajectory_path = directory / "trajectories.jsonl"
    scenario_path.write_text(scenarios_text, encoding="utf-8")
    started_at = now()
    stdout, stderr, image_id, restrictions = _run_restricted_container(
        scenarios_text, image=image, runner_path=runner_path, timeout=timeout
    )
    result_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    result_lines = [line for line in stdout.splitlines() if line.strip()]
    if len(result_lines) != len(scenarios):
        raise RuntimeError(f"Docker returned {len(result_lines)} results for {len(scenarios)} scenarios")
    results = [json.loads(line) for line in result_lines]
    batch_id = "docker-batch:" + _sha256_bytes(
        f"{image_id}:{_sha256_bytes(scenarios_text.encode('utf-8'))}".encode("utf-8")
    )[:24]
    trajectories = [
        docker_result_to_trajectory(
            scenario,
            result,
            image=image,
            image_id=image_id,
            restrictions=restrictions,
            result_path=result_path,
            result_line=index + 1,
            batch_id=batch_id,
        )
        for index, (scenario, result) in enumerate(zip(scenarios, results))
    ]
    trajectory_path.write_text(
        "".join(canonical_json(item) + "\n" for item in trajectories), encoding="utf-8"
    )
    imported = import_trajectories(store, trajectory_path)
    dataset = export_trajectories(store, directory / "dataset")
    completed_at = now()
    type_counts = dict(sorted(Counter(item["vulnerability_type"] for item in trajectories).items()))
    obstacle_counts = dict(sorted(Counter(item["obstacle"] for item in results).items()))
    manifest = {
        "schema": "vulntools/docker-trajectory-batch/v1",
        "batch_id": batch_id,
        "created_at": completed_at,
        "started_at": started_at,
        "completed_at": completed_at,
        "image": image,
        "image_id": image_id,
        "restrictions": restrictions,
        "runner": {
            "path": str(runner_path),
            "sha256": _sha256_file(runner_path),
        },
        "counts": {
            "requested": count,
            "executed": len(results),
            "succeeded": sum(item["success"] is True for item in results),
            "imported": imported["saved"],
            "technical_vulnerability": sum(item["category"] == "technical_vulnerability" for item in trajectories),
            "business_logic": sum(item["category"] == "business_logic" for item in trajectories),
        },
        "vulnerability_types": type_counts,
        "obstacles": obstacle_counts,
        "artifacts": {
            "scenario_input": {"path": scenario_path.name, "sha256": _sha256_file(scenario_path)},
            "container_results": {"path": result_path.name, "sha256": _sha256_file(result_path)},
            "container_stderr": {"path": stderr_path.name, "sha256": _sha256_file(stderr_path)},
            "trajectories": {"path": trajectory_path.name, "sha256": _sha256_file(trajectory_path)},
            "dataset": dataset,
        },
        "contains_internal_reasoning": False,
        "real_world_vulnerabilities_verified": 0,
        "scope": "Executed Docker canaries in synthetic authorized scenarios only.",
    }
    manifest_path = directory / "docker-run-manifest.json"
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return {**manifest, "manifest": str(manifest_path), "database_summary": store.trajectory_summary()}
