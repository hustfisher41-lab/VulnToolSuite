"""Structured, evidence-bound security test trajectories without hidden reasoning traces."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from collections import Counter
from typing import Any

from .models import canonical_json, now
from .storage import Store


SCHEMA = "vulntools/security-trajectory/v1"
ALLOWED_CATEGORIES = {"technical_vulnerability", "business_logic"}
FORBIDDEN_KEYS = {"chain_of_thought", "reasoning", "thoughts", "internal_monologue"}
REQUIRED_CHAIN_PHASES = (
    "define_scope",
    "form_hypothesis",
    "assess_obstacle",
    "recover_or_proceed",
    "execute_canary",
    "verify_evidence",
    "complete_task",
)
REQUIRED_OBSTACLES = {"none", "session_expired", "field_alias", "input_filter", "state_version"}
REQUIREMENT_DATASETS = {
    "technical_vulnerability": {
        "requirement_id": "3",
        "dataset_name_zh": "结构化漏洞渗透思维链数据库",
        "methods": {"xss", "sql_injection", "command_injection", "ssrf", "csrf"},
    },
    "business_logic": {
        "requirement_id": "4",
        "dataset_name_zh": "业务逻辑漏洞渗透思维链数据库",
        "methods": {
            "parameter_tampering", "mass_assignment", "authorization_replay",
            "duplicate_submission", "workflow_order_bypass",
        },
    },
}


def validate_trajectory(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Trajectory must be a JSON object")
    if FORBIDDEN_KEYS & set(value):
        raise ValueError("Internal reasoning traces are not accepted; store observable actions and evidence")
    required = {
        "schema_version", "task_id", "category", "vulnerability_type", "environment",
        "precondition", "steps", "success", "blocked", "evidence", "created_at",
        "is_simulated", "execution_ready",
    }
    missing = sorted(required - set(value))
    if missing:
        raise ValueError("Trajectory is missing fields: " + ", ".join(missing))
    if value["schema_version"] != SCHEMA:
        raise ValueError("Unsupported trajectory schema_version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{5,127}", str(value["task_id"])):
        raise ValueError("Invalid trajectory task_id")
    if value["category"] not in ALLOWED_CATEGORIES:
        raise ValueError("Unsupported trajectory category")
    if not isinstance(value["vulnerability_type"], str) or not value["vulnerability_type"].strip():
        raise ValueError("vulnerability_type must be nonempty")
    environment = value["environment"]
    if not isinstance(environment, dict) or not environment.get("kind") or environment.get("authorized") is not True:
        raise ValueError("Trajectory environment must explicitly assert authorized=true")
    for field in ("success", "blocked", "is_simulated", "execution_ready"):
        if type(value[field]) is not bool:
            raise ValueError(f"{field} must be boolean")
    if value["execution_ready"] and value["is_simulated"]:
        raise ValueError("A simulated trajectory cannot claim execution readiness")
    if not isinstance(value["steps"], list) or not value["steps"]:
        raise ValueError("Trajectory requires at least one observable step")
    for index, step in enumerate(value["steps"]):
        if not isinstance(step, dict) or FORBIDDEN_KEYS & set(step):
            raise ValueError(f"Invalid trajectory step {index}")
        required_step = {"observation", "action_type", "tool", "input", "result", "blocked", "evidence"}
        if required_step - set(step):
            raise ValueError(f"Trajectory step {index} is incomplete")
        if type(step["blocked"]) is not bool or not isinstance(step["evidence"], list):
            raise ValueError(f"Trajectory step {index} has invalid blocked/evidence fields")
    if not isinstance(value["evidence"], list):
        raise ValueError("evidence must be an array")
    events = value.get("runtime_events") or []
    if not isinstance(events, list):
        raise ValueError("runtime_events must be an array")
    for index, event in enumerate(events):
        if not isinstance(event, dict) or not all(event.get(key) for key in ("timestamp", "type")):
            raise ValueError(f"Runtime event {index} requires timestamp and type")
    return value


def _read_runtime_events(directory: Path, run: dict[str, Any]) -> list[dict[str, Any]]:
    variant = (run.get("verdict") or {}).get("variant")
    path = directory / str(variant) / "events.jsonl"
    if not variant or not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        if line.strip():
            item = json.loads(line)
            if item.get("run_id") == run.get("run_id"):
                events.append(item)
    return events


def trajectory_from_smoke(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a canary report to a transparent workflow trajectory.

    Fixture results remain explicitly simulated and never become evidence of real isolation or
    a real vulnerability. VM results are accepted only when the existing workflow marked them so.
    """
    if report.get("schema") != "vulntools/reproduction-smoke/v1":
        raise ValueError("Unsupported reproduction report")
    directory = Path(report["directory"]).resolve()
    runs = report.get("runs") or []
    runtime_events = [event for run in runs for event in _read_runtime_events(directory, run)]
    steps: list[dict[str, Any]] = [{
        "observation": "A paired authorization-boundary canary plan was generated.",
        "action_type": "prepare",
        "tool": "vulntools.reproduction",
        "input": {"mode": report["mode"], "recipe_sha256": report["recipe_sha256"]},
        "result": {"status": "planned", "sample_count": 2},
        "blocked": False,
        "recovery_strategy": None,
        "evidence": [str(directory / "plan.json")],
    }]
    for run in runs:
        verdict = run.get("verdict") or {}
        variant = str(verdict.get("variant") or "unknown")
        steps.append({
            "observation": f"The {variant} canary returned evidence-bound runtime artifacts.",
            "action_type": "execute_canary" if report.get("sample_executed") else "evaluate_fixture",
            "tool": "attested_vm" if report.get("sample_executed") else "fixture_backend",
            "input": {"variant": variant, "sample_sha256": run.get("sample_sha256")},
            "result": {"run_id": run.get("run_id"), "verdict": verdict.get("status"),
                       "destroyed": run.get("destroyed"), "issues": verdict.get("issues") or []},
            "blocked": verdict.get("status") != "passed",
            "recovery_strategy": "Inspect runtime evidence and rerun on an accepted backend" if verdict.get("status") != "passed" else None,
            "evidence": [str(directory / variant / name) for name in
                         ("run-report.json", "result.json", "events.jsonl", "stdout.txt")
                         if (directory / variant / name).is_file()],
        })
    status = report.get("status")
    success = status in {"fixture_passed", "canary_passed"}
    is_simulated = bool(report.get("is_simulated"))
    trajectory = {
        "schema_version": SCHEMA,
        "task_id": "trajectory:" + hashlib.sha256(
            f"{report.get('nonce')}:{report.get('recipe_sha256')}".encode("utf-8")
        ).hexdigest()[:24],
        "category": "business_logic",
        "vulnerability_type": "authorization_boundary",
        "environment": {
            "kind": "fixture" if is_simulated else "attested_vm",
            "authorized": True,
            "scope": "built-in harmless paired canary only",
            "backend": report.get("backend"),
        },
        "precondition": "Use only the built-in nonce-bound canary; no public target or arbitrary PoC execution.",
        "steps": steps,
        "success": success,
        "blocked": status in {"blocked", "blocked_or_failed"},
        "recovery_strategy": "Configure and attest the independent VM backend" if status in {"blocked", "blocked_or_failed"} else None,
        "evidence": [{"path": str(directory / "verification-report.json"),
                      "recipe_sha256": report.get("recipe_sha256")}],
        "runtime_events": runtime_events,
        "created_at": report.get("created_at") or now(),
        "completed_at": now(),
        "is_simulated": is_simulated,
        "execution_ready": bool(report.get("execution_ready")),
        "real_vulnerability_verified": bool(report.get("real_vulnerability_verified")),
        "outcome_scope": "workflow_canary_only",
    }
    return validate_trajectory(trajectory)


def import_trajectories(store: Store, path: str | Path) -> dict[str, Any]:
    source = Path(path)
    content = source.read_text(encoding="utf-8-sig")
    try:
        parsed = json.loads(content)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        items = [json.loads(line) for line in content.splitlines() if line.strip()]
    saved = [store.save_trajectory(validate_trajectory(item)) for item in items]
    return {"input": str(source.resolve()), "received": len(items), "saved": len(saved),
            "task_ids": [item["task_id"] for item in saved]}


def export_trajectories(store: Store, output: str | Path) -> dict[str, Any]:
    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    trajectories = store.trajectories_page(limit=100, offset=0)
    # Export every page without imposing the API page cap.
    total = store.trajectory_summary()["total"]
    for offset in range(100, total, 100):
        trajectories.extend(store.trajectories_page(limit=100, offset=offset))
    trajectory_path = directory / "trajectories.jsonl"
    sft_path = directory / "trajectory_sft.jsonl"
    trajectory_path.write_text("".join(canonical_json(item) + "\n" for item in trajectories), encoding="utf-8")
    sft_rows = []
    for item in trajectories:
        sft_rows.append({
            "instruction": "根据授权安全测试轨迹，总结可观察步骤、结果和证据边界。不要推断未记录的内部推理或漏洞事实。",
            "input": canonical_json({
                "task_id": item["task_id"], "category": item["category"],
                "vulnerability_type": item["vulnerability_type"], "environment": item["environment"],
                "precondition": item["precondition"], "steps": item["steps"],
            }),
            "output": canonical_json({
                "success": item["success"], "blocked": item["blocked"],
                "recovery_strategy": item.get("recovery_strategy"), "evidence": item["evidence"],
                "is_simulated": item["is_simulated"],
            }),
            "metadata": {"task_id": item["task_id"], "schema_version": item["schema_version"]},
        })
    sft_path.write_text("".join(canonical_json(item) + "\n" for item in sft_rows), encoding="utf-8")
    manifest = {"schema": "vulntools/security-trajectory-dataset/v1", "created_at": now(),
                "counts": {"trajectories": len(trajectories), "sft": len(sft_rows)},
                "files": {"trajectories": trajectory_path.name, "sft": sft_path.name},
                "contains_internal_reasoning": False,
                "real_executions": sum(not item["is_simulated"] for item in trajectories),
                "docker_lab_executions": sum(
                    item.get("environment", {}).get("kind") == "docker_canary_lab" for item in trajectories
                ),
                "attested_vm_executions": sum(
                    item.get("environment", {}).get("kind") == "attested_vm" for item in trajectories
                )}
    (directory / "manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return {**manifest, "output": str(directory)}


def _requirement_acceptance(
    category: str,
    trajectories: list[dict[str, Any]],
    *,
    minimum_required: int = 1000,
) -> dict[str, Any]:
    config = REQUIREMENT_DATASETS[category]
    method_counts = Counter(str(item.get("vulnerability_type")) for item in trajectories)
    obstacle_counts = Counter(
        str((item.get("obstacle_condition") or {}).get("code")) for item in trajectories
    )
    matrix = Counter(
        (
            str(item.get("vulnerability_type")),
            str((item.get("obstacle_condition") or {}).get("code")),
        )
        for item in trajectories
    )
    successful = sum(item.get("success") is True for item in trajectories)
    complete = sum(
        item.get("chain_complete") is True
        and (item.get("structured_pentest_chain") or {}).get("complete") is True
        and (item.get("completion") or {}).get("task_completed") is True
        and [step.get("action_type") for step in item.get("steps") or []]
        == list(REQUIRED_CHAIN_PHASES)
        for item in trajectories
    )
    obstacle_process_complete = sum(
        bool((item.get("obstacle_condition") or {}).get("assessment_zh"))
        and bool((item.get("obstacle_condition") or {}).get("strategy_zh"))
        and (item.get("obstacle_condition") or {}).get("recovery_verified") is True
        for item in trajectories
    )
    expected_matrix = {
        f"{method}|{obstacle}": matrix[(method, obstacle)]
        for method in sorted(config["methods"])
        for obstacle in sorted(REQUIRED_OBSTACLES)
    }
    checks = {
        "minimum_count_met": len(trajectories) >= minimum_required,
        "all_tasks_succeeded": successful == len(trajectories),
        "all_chains_complete": complete == len(trajectories),
        "all_obstacle_processes_complete": obstacle_process_complete == len(trajectories),
        "required_methods_present": set(method_counts) == config["methods"],
        "required_obstacles_present": set(obstacle_counts) == REQUIRED_OBSTACLES,
        "every_method_obstacle_pair_present": all(expected_matrix.values()),
        "no_internal_reasoning": all(
            item.get("contains_internal_reasoning") is False for item in trajectories
        ),
        "synthetic_boundary_preserved": all(
            item.get("synthetic_scenario") is True
            and item.get("real_vulnerability_verified") is False
            for item in trajectories
        ),
    }
    report = {
        "requirement_id": config["requirement_id"],
        "dataset_name_zh": config["dataset_name_zh"],
        "minimum_required": minimum_required,
        "actual_count": len(trajectories),
        "successful_count": successful,
        "complete_chain_count": complete,
        "obstacle_process_complete_count": obstacle_process_complete,
        "steps_per_chain": len(REQUIRED_CHAIN_PHASES),
        "methods": dict(sorted(method_counts.items())),
        "obstacles": dict(sorted(obstacle_counts.items())),
        "method_obstacle_matrix": expected_matrix,
        "checks": checks,
        "accepted": all(checks.values()),
    }
    if not report["accepted"]:
        failed = [name for name, passed in checks.items() if not passed]
        raise ValueError(f"Requirement {config['requirement_id']} acceptance failed: {failed}")
    return report


def _write_requirement_tables(
    store: Store,
    category: str,
    trajectories: list[dict[str, Any]],
    acceptance: dict[str, Any],
) -> None:
    store.db.executescript("""
        CREATE TABLE dataset_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL);
        CREATE TABLE structured_pentest_chains (
            task_id TEXT PRIMARY KEY,
            requirement_id TEXT NOT NULL,
            category TEXT NOT NULL,
            attack_method TEXT NOT NULL,
            attack_method_zh TEXT NOT NULL,
            obstacle_condition TEXT NOT NULL,
            success INTEGER NOT NULL CHECK(success=1),
            chain_complete INTEGER NOT NULL CHECK(chain_complete=1),
            step_count INTEGER NOT NULL,
            chain_payload TEXT NOT NULL,
            FOREIGN KEY(task_id) REFERENCES security_trajectories(task_id) ON DELETE CASCADE);
        CREATE INDEX structured_pentest_chains_method_obstacle
            ON structured_pentest_chains(attack_method, obstacle_condition, success);
    """)
    metadata = {
        "schema": "vulntools/structured-pentest-chain-database/v1",
        "category": category,
        "requirement_id": acceptance["requirement_id"],
        "dataset_name_zh": acceptance["dataset_name_zh"],
        "minimum_required": acceptance["minimum_required"],
        "actual_count": acceptance["actual_count"],
        "successful_count": acceptance["successful_count"],
        "complete_chain_count": acceptance["complete_chain_count"],
        "methods": acceptance["methods"],
        "obstacles": acceptance["obstacles"],
        "acceptance_checks": acceptance["checks"],
        "contains_internal_reasoning": False,
        "scope": "authorized synthetic Docker canary only",
    }
    with store.db:
        for key, value in metadata.items():
            store.db.execute(
                "INSERT INTO dataset_metadata VALUES (?,?)", (key, canonical_json(value))
            )
        for item in trajectories:
            profile = (item.get("structured_pentest_chain") or {}).get("method_profile") or {}
            obstacle = item.get("obstacle_condition") or {}
            chain_payload = {
                "task_id": item["task_id"],
                "task_objective_zh": item.get("task_objective_zh"),
                "success_criteria_zh": item.get("success_criteria_zh"),
                "obstacle_condition": obstacle,
                "structured_pentest_chain": item.get("structured_pentest_chain"),
                "steps": item["steps"],
                "completion": item.get("completion"),
                "evidence": item["evidence"],
            }
            store.db.execute(
                """INSERT INTO structured_pentest_chains
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    item["task_id"], acceptance["requirement_id"], category,
                    item["vulnerability_type"], profile.get("name_zh"), obstacle.get("code"),
                    1, 1, len(item["steps"]), canonical_json(chain_payload),
                ),
            )


def export_category_databases(
    store: Store,
    output: str | Path,
    *,
    expected_per_category: int | None = None,
    minimum_required: int = 1000,
    environment_kind: str = "docker_canary_lab",
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export Docker trajectories into one self-contained SQLite database per category."""
    if expected_per_category is not None and (
        type(expected_per_category) is not int or expected_per_category < 1
    ):
        raise ValueError("expected_per_category must be a positive integer")
    if type(minimum_required) is not int or minimum_required < 1:
        raise ValueError("minimum_required must be a positive integer")
    if not isinstance(environment_kind, str) or not environment_kind.strip():
        raise ValueError("environment_kind must be nonempty")

    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    names = {
        "technical_vulnerability": "technical-vulnerabilities.sqlite",
        "business_logic": "business-logic-vulnerabilities.sqlite",
    }
    rows = store.db.execute(
        """SELECT category,payload FROM security_trajectories
           WHERE environment_kind=? ORDER BY category,task_id""",
        (environment_kind,),
    ).fetchall()
    grouped = {category: [] for category in names}
    for row in rows:
        category = str(row[0])
        if category in grouped:
            grouped[category].append(validate_trajectory(json.loads(row[1])))

    counts = {category: len(items) for category, items in grouped.items()}
    if expected_per_category is not None and any(
        count != expected_per_category for count in counts.values()
    ):
        raise ValueError(
            f"Expected {expected_per_category} {environment_kind} trajectories per category; got {counts}"
        )

    acceptance_reports = {
        category: _requirement_acceptance(category, items, minimum_required=minimum_required)
        for category, items in grouped.items()
    }
    targets = {category: directory / filename for category, filename in names.items()}
    existing = [str(path) for path in targets.values() if path.exists()]
    if existing and not overwrite:
        raise FileExistsError("Refusing to overwrite existing databases: " + ", ".join(existing))

    database_reports: dict[str, Any] = {}
    for category, target in targets.items():
        temporary = target.with_suffix(target.suffix + ".building")
        if temporary.exists():
            temporary.unlink()
        try:
            with Store(temporary) as category_store:
                for trajectory in grouped[category]:
                    category_store.save_trajectory(trajectory)
                _write_requirement_tables(
                    category_store, category, grouped[category], acceptance_reports[category]
                )
                summary = category_store.trajectory_summary()
                quick_check = str(category_store.db.execute("PRAGMA quick_check").fetchone()[0])
                foreign_key_violations = len(category_store.db.execute("PRAGMA foreign_key_check").fetchall())
            if quick_check != "ok" or foreign_key_violations:
                raise RuntimeError(
                    f"SQLite validation failed for {category}: quick_check={quick_check}, "
                    f"foreign_key_violations={foreign_key_violations}"
                )
            # Path.replace uses the platform's atomic replacement primitive, so an
            # existing valid database is not removed before the new one is complete.
            temporary.replace(target)
        finally:
            if temporary.exists():
                temporary.unlink()

        digest = hashlib.sha256()
        with target.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        connection = sqlite3.connect(target)
        try:
            persisted_categories = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT category,count(*) FROM security_trajectories GROUP BY category"
                )
            }
        finally:
            connection.close()
        if persisted_categories != {category: counts[category]}:
            raise RuntimeError(f"Category isolation failed for {target}: {persisted_categories}")
        database_reports[category] = {
            "path": str(target),
            "filename": target.name,
            "bytes": target.stat().st_size,
            "sha256": digest.hexdigest(),
            "quick_check": quick_check,
            "foreign_key_violations": foreign_key_violations,
            "summary": summary,
            "acceptance": acceptance_reports[category],
        }

    manifest = {
        "schema": "vulntools/security-trajectory-category-databases/v1",
        "created_at": now(),
        "environment_kind": environment_kind,
        "expected_per_category": expected_per_category,
        "counts": counts,
        "databases": database_reports,
        "requirements": {
            report["requirement_id"]: report for report in acceptance_reports.values()
        },
        "contains_internal_reasoning": False,
        "real_world_vulnerabilities_verified": 0,
        "scope": "Executed Docker canaries in synthetic authorized scenarios only.",
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return {**manifest, "manifest": str(manifest_path)}
