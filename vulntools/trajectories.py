"""Structured, evidence-bound security test trajectories without hidden reasoning traces."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .models import canonical_json, now
from .storage import Store


SCHEMA = "vulntools/security-trajectory/v1"
ALLOWED_CATEGORIES = {"technical_vulnerability", "business_logic"}
FORBIDDEN_KEYS = {"chain_of_thought", "reasoning", "thoughts", "internal_monologue"}


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
                "real_executions": sum(not item["is_simulated"] for item in trajectories)}
    (directory / "manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return {**manifest, "output": str(directory)}
