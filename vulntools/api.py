"""Optional local read-only HTTP API, sharing the CLI's storage and encoder."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from .analytics import drift_report, quality_report
from .collection import collection_status
from .embedding import DomainAdapterEncoder, HashEncoder, LocalSentenceEncoder, classify_text, cluster_records
from .models import digest
from .processing import alignment_report
from .search import SCALABLE_SCAN_THRESHOLD, index_status, record_similarity, search
from .storage import Store


def _platform_summary(store: Store, encoder: Any, db_path: str | Path) -> dict[str, Any]:
    fields = ("title", "description", "components", "weaknesses", "severity", "poc", "patch")
    aggregate = store.db.execute(
        """SELECT count(*),
                  sum(CASE WHEN json_extract(payload,'$.status')='active' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.title')='missing' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.description')='missing' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.components')='missing' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.weaknesses')='missing' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.severity')='missing' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.poc')='missing' THEN 1 ELSE 0 END),
                  sum(CASE WHEN json_extract(payload,'$.status')='active'
                                AND json_extract(payload,'$.field_states.patch')='missing' THEN 1 ELSE 0 END)
           FROM canonical"""
    ).fetchone()
    total = int(aggregate[0] or 0)
    active = int(aggregate[1] or 0)
    rejected = total - active
    sources = {row[0]: row[1] for row in store.db.execute(
        "SELECT source,count(*) FROM source_latest GROUP BY source ORDER BY source"
    )}
    severity = {str(row[0] or "unknown"): row[1] for row in store.db.execute(
        """SELECT json_extract(payload,'$.fields.severity'),count(*) FROM canonical
           WHERE json_extract(payload,'$.status')='active'
           GROUP BY json_extract(payload,'$.fields.severity')"""
    )}
    missing_fields = {field: int(aggregate[index + 2] or 0) for index, field in enumerate(fields)}
    top_weaknesses = {row[0]: row[1] for row in store.db.execute(
        """SELECT weakness.value,count(*) FROM canonical c,
                  json_each(c.payload,'$.fields.weaknesses') weakness
           WHERE json_extract(c.payload,'$.status')='active'
           GROUP BY weakness.value ORDER BY count(*) DESC,weakness.value LIMIT 12"""
    )}
    poc_artifacts = int(store.db.execute("SELECT count(*) FROM poc_artifacts").fetchone()[0])
    poc_linked = int(store.db.execute(
        """SELECT count(DISTINCT l.vuln_id) FROM poc_vulnerability_links l
           JOIN canonical c ON c.vuln_id=l.vuln_id
           WHERE json_extract(c.payload,'$.status')='active'"""
    ).fetchone()[0])
    model_id = digest(encoder.manifest)
    indexed = int(store.db.execute(
        """SELECT count(*) FROM vectors v JOIN canonical c
           ON c.vuln_id=v.vuln_id AND c.revision=v.revision
           WHERE v.model_id=? AND json_extract(c.payload,'$.status')='active'""",
        (model_id,),
    ).fetchone()[0])
    vector_views = int(store.db.execute(
        """SELECT count(*) FROM vector_views vv JOIN canonical c
           ON c.vuln_id=vv.vuln_id AND c.revision=vv.revision
           WHERE vv.model_id=? AND json_extract(c.payload,'$.status')='active'""",
        (model_id,),
    ).fetchone()[0])
    aggregate_views = int(store.db.execute(
        """SELECT count(*) FROM vector_views vv JOIN canonical c
           ON c.vuln_id=vv.vuln_id AND c.revision=vv.revision
           WHERE vv.model_id=? AND vv.view_name='aggregate'
             AND json_extract(c.payload,'$.status')='active'""",
        (model_id,),
    ).fetchone()[0])
    job_status = {str(row[0]): row[1] for row in store.db.execute(
        "SELECT status,count(*) FROM jobs GROUP BY status ORDER BY status"
    )}
    trajectories = store.trajectory_summary()
    latest_fetch = store.db.execute(
        "SELECT max(json_extract(payload,'$.fetched_at')) FROM source_latest"
    ).fetchone()[0]
    dataset = {"status": "not_connected"}
    manifest_path = Path(db_path).resolve().parent / "vulnerability-training-v2" / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            dataset = {
                "status": "available",
                "dataset_id": manifest.get("dataset_id"),
                "created_at": manifest.get("created_at"),
                "counts": manifest.get("counts") or {},
                "validation": manifest.get("validation") or {},
                "requirements_fully_met": (manifest.get("readiness") or {}).get("requirements_fully_met", False),
            }
        except (OSError, json.JSONDecodeError):
            dataset = {"status": "invalid_manifest"}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": {
            "records": total,
            "active": active,
            "rejected": rejected,
            "sources": sources,
            "severity": severity,
            "top_weaknesses": top_weaknesses,
            "missing_fields": missing_fields,
            "latest_fetch": latest_fetch,
            "poc_artifacts": poc_artifacts,
            "poc_linked_records": poc_linked,
            "patch_records": active - missing_fields["patch"],
        },
        "index": {
            "model_id": model_id,
            "encoder": encoder.manifest,
            "indexed_records": indexed,
            "missing_records": max(0, active - indexed),
            "vector_views": vector_views,
            "ready": active > 0 and indexed == active and aggregate_views == indexed,
            "backend": "sqlite_two_stage" if indexed > SCALABLE_SCAN_THRESHOLD else "sqlite_exact",
        },
        "dataset": dataset,
        "trajectories": trajectories,
        "jobs": job_status,
        "sandbox": {
            "execution_ready": False,
            "status": "not_configured",
            "fixture_workflows": trajectories["simulated"],
            "note": "Fixture trajectories are observable workflow tests, not proof of real isolation. No attested independent VM backend is connected.",
        },
    }


def create_app(db_path: str | Path, model_path: str | None = None, dimension: int = 512, adapter_path: str | None = None):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse
        from pydantic import BaseModel, Field
    except ImportError as exc:
        raise RuntimeError("Install the api extra to run the HTTP interface") from exc
    base_encoder = LocalSentenceEncoder(model_path) if model_path else HashEncoder(dimension)
    encoder = DomainAdapterEncoder.load(base_encoder, adapter_path) if adapter_path else base_encoder
    app = FastAPI(title="VulnToolSuite", version="0.2.0", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        from .dashboard import DASHBOARD_HTML
        return DASHBOARD_HTML

    class SearchRequest(BaseModel):
        query: str = ""
        poc: str = ""
        component: str | None = None
        version: str | None = None
        cpes: list[str] | None = None
        severity: str | None = None
        weakness: str | None = None
        source: str | None = None
        top_k: int = Field(default=10, ge=1, le=100)
        offset: int = Field(default=0, ge=0, le=10000)
        mode: str = Field(default="hybrid", pattern="^(hybrid|dense|sparse)$")
        min_similarity: float | None = Field(default=None, ge=-1, le=1)

    class SimilarityRequest(BaseModel):
        left: str
        right: str
        views: list[str] | None = None

    class ClassificationRequest(BaseModel):
        text: str = Field(min_length=1, max_length=200000)
        top_k: int = Field(default=5, ge=1, le=100)

    class ClusterRequest(BaseModel):
        clusters: int = Field(default=8, ge=1, le=100)

    class DriftRequest(BaseModel):
        baseline: dict[str, Any]
        threshold: float = Field(default=0.10, gt=0, le=1)

    @app.get("/health")
    def health():
        with Store(db_path) as store:
            count = store.record_count()
        return {"status": "ok", "records": count, "encoder": encoder.manifest, "sandbox_execution": False}

    @app.get("/records")
    def records(limit: int = 20, offset: int = 0):
        if not 1 <= limit <= 100 or offset < 0:
            raise HTTPException(422, "limit must be 1..100 and offset nonnegative")
        with Store(db_path) as store:
            total = store.record_count()
            items = store.records_page(limit=limit, offset=offset)
        return {"total": total, "items": items}

    @app.get("/analytics/summary")
    def summary():
        with Store(db_path) as store:
            return _platform_summary(store, encoder, db_path)

    @app.get("/trajectories")
    def trajectories(limit: int = 20, offset: int = 0):
        if not 1 <= limit <= 100 or offset < 0:
            raise HTTPException(422, "limit must be 1..100 and offset nonnegative")
        with Store(db_path) as store:
            summary = store.trajectory_summary()
            items = store.trajectories_page(limit=limit, offset=offset)
        return {"total": summary["total"], "items": items}

    @app.get("/trajectories/{task_id:path}")
    def trajectory(task_id: str):
        with Store(db_path) as store:
            item = store.trajectory(task_id)
        if item is None:
            raise HTTPException(404, "Trajectory not found")
        return item

    @app.get("/index/status")
    def vector_index_status():
        with Store(db_path) as store:
            return index_status(store, encoder)

    @app.get("/collection/status")
    def source_collection_status():
        with Store(db_path) as store:
            return collection_status(store)

    @app.get("/records/{vuln_id}")
    def record(vuln_id: str):
        with Store(db_path) as store:
            item = store.record(vuln_id)
        if item is not None:
            return item
        raise HTTPException(404, "Vulnerability not found")

    # Assign the concrete annotation: the request class is local to this factory.
    def query(body):
        try:
            with Store(db_path) as store:
                return {"hits": search(store, encoder, **body.model_dump())}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    query.__annotations__["body"] = SearchRequest
    app.post("/search")(query)

    def similarity(body):
        try:
            with Store(db_path) as store:
                return record_similarity(store, encoder, body.left, body.right, body.views)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    similarity.__annotations__["body"] = SimilarityRequest
    app.post("/similarity")(similarity)

    def classify(body):
        with Store(db_path) as store:
            return {"predictions": classify_text(store.records(), encoder, body.text, body.top_k)}
    classify.__annotations__["body"] = ClassificationRequest
    app.post("/classify")(classify)

    def clusters(body):
        try:
            with Store(db_path) as store:
                return cluster_records(store.records(), encoder, body.clusters)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    clusters.__annotations__["body"] = ClusterRequest
    app.post("/clusters")(clusters)

    @app.get("/analytics/quality")
    def quality():
        with Store(db_path) as store:
            return quality_report(store.records())

    @app.get("/analytics/alignment")
    def alignment():
        with Store(db_path) as store:
            return alignment_report(store.records())

    def drift(body):
        try:
            with Store(db_path) as store:
                current = quality_report(store.records())
            return drift_report(current, body.baseline, body.threshold)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
    drift.__annotations__["body"] = DriftRequest
    app.post("/analytics/drift")(drift)

    return app
