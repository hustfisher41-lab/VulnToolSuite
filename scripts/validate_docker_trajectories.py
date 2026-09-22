"""Independently validate a Docker canary trajectory batch and its database rows."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sqlite3


EXPECTED_RESTRICTIONS = {
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
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(database: Path, directory: Path, expected_count: int) -> dict:
    manifest_path = directory / "docker-run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "vulntools/docker-trajectory-batch/v1":
        raise ValueError("Unsupported Docker trajectory manifest")
    if manifest.get("counts", {}).get("executed") != expected_count:
        raise ValueError("Manifest executed count mismatch")
    if manifest.get("counts", {}).get("succeeded") != expected_count:
        raise ValueError("Manifest success count mismatch")
    if set(manifest.get("restrictions") or []) != EXPECTED_RESTRICTIONS:
        raise ValueError("Manifest restriction set mismatch")

    checked_artifacts = {}
    for name in ("scenario_input", "container_results", "container_stderr", "trajectories"):
        entry = manifest["artifacts"][name]
        path = directory / entry["path"]
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            raise ValueError(f"Artifact hash mismatch: {name}")
        checked_artifacts[name] = actual

    trajectory_lines = [
        json.loads(line)
        for line in (directory / manifest["artifacts"]["trajectories"]["path"])
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    if len(trajectory_lines) != expected_count:
        raise ValueError("Trajectory artifact row count mismatch")

    connection = sqlite3.connect(f"file:{database.resolve()}?mode=ro", uri=True)
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise ValueError(f"SQLite quick_check failed: {quick_check}")
        payloads = [
            json.loads(row[0])
            for row in connection.execute(
                "SELECT payload FROM security_trajectories WHERE environment_kind='docker_canary_lab'"
            )
        ]
    finally:
        connection.close()
    if len(payloads) != expected_count:
        raise ValueError("Database Docker trajectory count mismatch")

    task_ids = {item["task_id"] for item in payloads}
    if len(task_ids) != expected_count:
        raise ValueError("Duplicate Docker task IDs")
    for item in payloads:
        if not (
            item.get("success") is True
            and item.get("is_simulated") is False
            and item.get("execution_ready") is True
            and item.get("synthetic_scenario") is True
            and item.get("real_vulnerability_verified") is False
            and item.get("contains_internal_reasoning") is False
            and item.get("outcome_scope") == "docker_lab_canary_only"
        ):
            raise ValueError(f"Trajectory boundary mismatch: {item.get('task_id')}")
        environment = item.get("environment") or {}
        if environment.get("authorized") is not True:
            raise ValueError(f"Unauthorized trajectory: {item.get('task_id')}")
        if environment.get("production_isolation_attested") is not False:
            raise ValueError(f"Invalid isolation claim: {item.get('task_id')}")
        if set(environment.get("restrictions") or []) != EXPECTED_RESTRICTIONS:
            raise ValueError(f"Restriction mismatch: {item.get('task_id')}")

    type_counts = dict(sorted(Counter(item["vulnerability_type"] for item in payloads).items()))
    category_counts = dict(sorted(Counter(item["category"] for item in payloads).items()))
    if type_counts != manifest.get("vulnerability_types"):
        raise ValueError("Vulnerability type distribution mismatch")
    expected_categories = {
        "business_logic": manifest["counts"]["business_logic"],
        "technical_vulnerability": manifest["counts"]["technical_vulnerability"],
    }
    if category_counts != expected_categories:
        raise ValueError("Category distribution mismatch")
    evidence_digests = {
        item["evidence"][0]["evidence_digest"]
        for item in payloads
    }
    if len(evidence_digests) != expected_count:
        raise ValueError("Evidence digests are not unique")
    return {
        "status": "passed",
        "database": str(database.resolve()),
        "input": str(directory.resolve()),
        "sqlite_quick_check": quick_check,
        "trajectories": len(payloads),
        "unique_task_ids": len(task_ids),
        "unique_evidence_digests": len(evidence_digests),
        "categories": category_counts,
        "vulnerability_types": type_counts,
        "artifacts": checked_artifacts,
        "contains_internal_reasoning": False,
        "real_world_vulnerabilities_verified": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-count", type=int, default=1500)
    args = parser.parse_args()
    report = validate(args.db, args.input, args.expected_count)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
