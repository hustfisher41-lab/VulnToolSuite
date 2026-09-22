"""Independently validate the two requirement-oriented trajectory databases."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3


EXPECTED = {
    "technical_vulnerability": {
        "filename": "technical-vulnerabilities.sqlite",
        "requirement_id": "3",
        "methods": {"xss", "sql_injection", "command_injection", "ssrf", "csrf"},
    },
    "business_logic": {
        "filename": "business-logic-vulnerabilities.sqlite",
        "requirement_id": "4",
        "methods": {
            "parameter_tampering", "mass_assignment", "authorization_replay",
            "duplicate_submission", "workflow_order_bypass",
        },
    },
}
OBSTACLES = {"none", "session_expired", "field_alias", "input_filter", "state_version"}
PHASES = [
    "define_scope", "form_hypothesis", "assess_obstacle", "recover_or_proceed",
    "execute_canary", "verify_evidence", "complete_task",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(directory: Path, expected_per_category: int) -> dict:
    directory = directory.resolve()
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "vulntools/security-trajectory-category-databases/v1":
        raise ValueError("Unsupported category database manifest")
    reports = {}
    for category, config in EXPECTED.items():
        entry = manifest["databases"][category]
        path = directory / config["filename"]
        if entry["filename"] != config["filename"] or _sha256(path) != entry["sha256"]:
            raise ValueError(f"File identity mismatch for {category}")
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
            foreign_key_violations = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            category_counts = dict(connection.execute(
                "SELECT category,count(*) FROM security_trajectories GROUP BY category"
            ).fetchall())
            rows = connection.execute(
                """SELECT task_id,requirement_id,category,attack_method,attack_method_zh,
                          obstacle_condition,success,chain_complete,step_count,chain_payload
                   FROM structured_pentest_chains ORDER BY task_id"""
            ).fetchall()
            metadata = {
                key: json.loads(value)
                for key, value in connection.execute("SELECT key,value FROM dataset_metadata")
            }
            trajectory_ids = {
                row[0] for row in connection.execute("SELECT task_id FROM security_trajectories")
            }
        finally:
            connection.close()
        if quick_check != "ok" or foreign_key_violations:
            raise ValueError(f"SQLite validation failed for {category}")
        if category_counts != {category: expected_per_category} or len(rows) != expected_per_category:
            raise ValueError(f"Count/category isolation failed for {category}")
        if {row[0] for row in rows} != trajectory_ids:
            raise ValueError(f"Structured chain/task identity mismatch for {category}")

        methods = Counter(row[3] for row in rows)
        obstacles = Counter(row[5] for row in rows)
        matrix = Counter((row[3], row[5]) for row in rows)
        for row in rows:
            payload = json.loads(row[9])
            if not (
                row[1] == config["requirement_id"]
                and row[2] == category
                and row[4]
                and row[6] == 1
                and row[7] == 1
                and row[8] == len(PHASES)
                and [step.get("action_type") for step in payload.get("steps") or []] == PHASES
                and (payload.get("completion") or {}).get("task_completed") is True
                and (payload.get("obstacle_condition") or {}).get("recovery_verified") is True
            ):
                raise ValueError(f"Incomplete chain row: {row[0]}")
        if set(methods) != config["methods"] or set(obstacles) != OBSTACLES or len(matrix) != 25:
            raise ValueError(f"Method/obstacle coverage failed for {category}")
        if not (
            metadata.get("requirement_id") == config["requirement_id"]
            and metadata.get("actual_count") == expected_per_category
            and metadata.get("successful_count") == expected_per_category
            and metadata.get("complete_chain_count") == expected_per_category
            and all((metadata.get("acceptance_checks") or {}).values())
        ):
            raise ValueError(f"Metadata acceptance failed for {category}")
        reports[category] = {
            "requirement_id": config["requirement_id"],
            "database": str(path),
            "sha256": entry["sha256"],
            "quick_check": quick_check,
            "foreign_key_violations": foreign_key_violations,
            "trajectories": len(rows),
            "successful_complete_chains": len(rows),
            "methods": dict(sorted(methods.items())),
            "obstacles": dict(sorted(obstacles.items())),
            "method_obstacle_pairs": len(matrix),
        }
    return {
        "status": "passed",
        "input": str(directory),
        "expected_per_category": expected_per_category,
        "requirements": reports,
        "contains_internal_reasoning": False,
        "real_world_vulnerabilities_verified": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-per-category", type=int, default=1500)
    args = parser.parse_args()
    print(json.dumps(validate(args.input, args.expected_per_category), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
