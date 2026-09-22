"""One-command local acceptance closure using only capabilities that are actually available."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .embedding import Encoder
from .models import canonical_json, now
from .reproduction import smoke_workflow
from .sandbox import SandboxPolicy
from .search import index_status, search
from .storage import Store
from .training import build_training_dataset
from .trajectories import export_trajectories, trajectory_from_smoke


def _dataset(store: Store, db_path: str | Path, output: Path) -> dict[str, Any]:
    existing = Path(db_path).resolve().parent / "vulnerability-training-v2" / "manifest.json"
    if existing.is_file():
        manifest = json.loads(existing.read_text(encoding="utf-8-sig"))
        return {"mode": "existing", "manifest": str(existing), "counts": manifest.get("counts") or {},
                "validation": manifest.get("validation") or {}}
    built = build_training_dataset(store, output / "knowledge-dataset", max_records=100, include_code=False)
    return {"mode": "generated_sample", "manifest": str(output / "knowledge-dataset" / "manifest.json"),
            "counts": built.get("counts") or {}, "validation": built.get("validation") or {}}


def run_simple_closure(store: Store, db_path: str | Path, output: str | Path, encoder: Encoder,
                       *, query: str, expected_id: str | None = None) -> dict[str, Any]:
    directory = Path(output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    index = index_status(store, encoder)
    hits = search(store, encoder, query, top_k=5) if index["ready"] else []
    dataset = _dataset(store, db_path, directory)
    workflow = smoke_workflow(directory / "canary", mode="fixture", policy=SandboxPolicy())
    trajectory = trajectory_from_smoke(workflow)
    trajectory_saved = store.save_trajectory(trajectory)
    trajectory_dataset = export_trajectories(store, directory / "trajectory-dataset")
    expected_found = expected_id is None or any(
        hit["vuln_id"].casefold() == expected_id.casefold() for hit in hits
    )
    checks = {
        "database_has_records": store.record_count() > 0,
        "index_ready": bool(index["ready"]),
        "search_returned_results": bool(hits),
        "expected_vulnerability_found": expected_found,
        "knowledge_dataset_available": bool(dataset["counts"]),
        "trajectory_persisted": bool(store.trajectory(trajectory["task_id"])),
        "trajectory_dataset_available": trajectory_dataset["counts"]["trajectories"] > 0,
        "fixture_workflow_passed": workflow["status"] == "fixture_passed",
    }
    report = {
        "schema": "vulntools/simple-closure/v1",
        "created_at": now(),
        "status": "passed" if all(checks.values()) else "failed",
        "scope": "local_fixture_closure",
        "checks": checks,
        "database": {"records": store.record_count()},
        "index": index,
        "retrieval": {"query": query, "expected_id": expected_id,
                      "top_hits": [{"vuln_id": item["vuln_id"], "rank": item["rank"],
                                    "backend": item["index_backend"]} for item in hits]},
        "knowledge_dataset": dataset,
        "security_test": {"workflow_status": workflow["status"], "is_simulated": True,
                          "execution_ready": False, "trajectory": trajectory_saved},
        "trajectory_dataset": trajectory_dataset,
        "production_boundaries": {
            "full_production_closure": False,
            "docker_or_vm_execution": False,
            "runtime_isolation_verified": False,
            "real_vulnerability_verified": False,
            "vector_backend": index["backend"]["kind"],
            "note": "Usable local knowledge/retrieval/dataset/fixture trajectory closure; Docker/VM execution remains blocked.",
        },
    }
    (directory / "closure-report.json").write_text(canonical_json(report) + "\n", encoding="utf-8")
    return report
