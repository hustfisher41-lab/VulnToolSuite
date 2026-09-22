"""SQLite source history, canonical records, and versioned vector persistence."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator

from .models import SourceRecord, canonical_json, digest, now


class Store:
    def __init__(self, path: str | Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS source_history (
                source TEXT, source_id TEXT, content_hash TEXT, payload TEXT NOT NULL,
                PRIMARY KEY(source, source_id, content_hash));
            CREATE TABLE IF NOT EXISTS source_latest (
                source TEXT, source_id TEXT, payload TEXT NOT NULL,
                PRIMARY KEY(source, source_id));
            CREATE TABLE IF NOT EXISTS canonical (
                vuln_id TEXT PRIMARY KEY, revision TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS canonical_history (
                vuln_id TEXT, revision TEXT, payload TEXT NOT NULL,
                PRIMARY KEY(vuln_id, revision));
            CREATE TABLE IF NOT EXISTS vector_models (
                model_id TEXT PRIMARY KEY, manifest TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS vectors (
                model_id TEXT, vuln_id TEXT, revision TEXT NOT NULL,
                vector TEXT NOT NULL, input_text TEXT NOT NULL,
                PRIMARY KEY(model_id, vuln_id),
                FOREIGN KEY(model_id) REFERENCES vector_models(model_id));
            CREATE TABLE IF NOT EXISTS vector_views (
                model_id TEXT, vuln_id TEXT, revision TEXT NOT NULL, view_name TEXT,
                vector TEXT NOT NULL, input_text TEXT NOT NULL,
                PRIMARY KEY(model_id, vuln_id, view_name),
                FOREIGN KEY(model_id) REFERENCES vector_models(model_id));
            CREATE INDEX IF NOT EXISTS vector_views_lookup
                ON vector_views(model_id, view_name, vuln_id);
            CREATE TABLE IF NOT EXISTS jobs (
                job_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, status TEXT,
                started_at TEXT, ended_at TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS sync_state (
                source TEXT, stream TEXT, cursor TEXT NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY(source, stream));
            CREATE TABLE IF NOT EXISTS collection_failures (
                failure_id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL,
                item_id TEXT NOT NULL, url TEXT, error TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 1,
                first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, resolved_at TEXT,
                UNIQUE(source, item_id));
            CREATE TABLE IF NOT EXISTS poc_artifacts (
                artifact_id TEXT PRIMARY KEY, source TEXT NOT NULL, source_item_id TEXT NOT NULL,
                artifact_type TEXT NOT NULL, title TEXT NOT NULL, source_url TEXT NOT NULL,
                commit_ref TEXT, local_path TEXT, language TEXT NOT NULL, license TEXT,
                review_status TEXT NOT NULL, current_content_sha256 TEXT NOT NULL,
                first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, metadata TEXT NOT NULL,
                UNIQUE(source, source_item_id));
            CREATE TABLE IF NOT EXISTS poc_artifact_versions (
                artifact_id TEXT NOT NULL, content_sha256 TEXT NOT NULL, content TEXT NOT NULL,
                content_size INTEGER NOT NULL, collected_at TEXT NOT NULL,
                PRIMARY KEY(artifact_id, content_sha256),
                FOREIGN KEY(artifact_id) REFERENCES poc_artifacts(artifact_id));
            CREATE TABLE IF NOT EXISTS poc_vulnerability_links (
                artifact_id TEXT NOT NULL, vuln_id TEXT NOT NULL, relation TEXT NOT NULL,
                confidence REAL NOT NULL, evidence TEXT NOT NULL,
                PRIMARY KEY(artifact_id, vuln_id),
                FOREIGN KEY(artifact_id) REFERENCES poc_artifacts(artifact_id));
            CREATE INDEX IF NOT EXISTS poc_links_vulnerability
                ON poc_vulnerability_links(vuln_id, artifact_id);
            CREATE INDEX IF NOT EXISTS poc_artifacts_source_type
                ON poc_artifacts(source, artifact_type, review_status);
        """)
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        """Apply small, forward-only SQLite migrations without rewriting existing data."""
        self.db.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)""")
        if not self.db.execute("SELECT 1 FROM schema_migrations WHERE version=1").fetchone():
            self.db.execute(
                "INSERT INTO schema_migrations VALUES (1, 'baseline_existing_schema', ?)", (now(),)
            )
        if not self.db.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone():
            self.db.executescript("""
                CREATE TABLE security_trajectories (
                    task_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    category TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    environment_kind TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    blocked INTEGER NOT NULL,
                    is_simulated INTEGER NOT NULL,
                    execution_ready INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    payload TEXT NOT NULL);
                CREATE TABLE security_trajectory_steps (
                    task_id TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    action_type TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    blocked INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY(task_id, step_index),
                    FOREIGN KEY(task_id) REFERENCES security_trajectories(task_id) ON DELETE CASCADE);
                CREATE TABLE security_runtime_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    run_id TEXT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES security_trajectories(task_id) ON DELETE CASCADE);
                CREATE INDEX security_trajectories_category
                    ON security_trajectories(category, vulnerability_type, success);
                CREATE INDEX security_runtime_events_task
                    ON security_runtime_events(task_id, event_type, timestamp);
            """)
            self.db.execute(
                "INSERT INTO schema_migrations VALUES (2, 'structured_security_trajectories', ?)", (now(),)
            )
        self.db.commit()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    def save_sources_detailed(self, records: list[SourceRecord]) -> dict[str, int]:
        report = {"received": len(records), "changed": 0, "unchanged": 0, "stale": 0}
        with self.db:
            for record in records:
                payload = record.to_dict()
                fingerprint = digest({k: v for k, v in payload.items() if k != "fetched_at"})
                encoded = canonical_json(payload)
                previous = self.db.execute("SELECT payload FROM source_latest WHERE source=? AND source_id=?", (record.source, record.source_id)).fetchone()
                if previous:
                    old = json.loads(previous[0])
                    old_updated = old.get("source_updated_at")
                    if old_updated and not record.source_updated_at:
                        report["stale"] += 1
                        continue
                    if record.source_updated_at and old_updated:
                        from datetime import datetime
                        incoming_time = datetime.fromisoformat(record.source_updated_at.replace("Z", "+00:00"))
                        previous_time = datetime.fromisoformat(old_updated.replace("Z", "+00:00"))
                        if incoming_time < previous_time:
                            report["stale"] += 1
                            continue
                    if digest({k: v for k, v in old.items() if k != "fetched_at"}) == fingerprint:
                        report["unchanged"] += 1
                        continue
                self.db.execute("INSERT OR IGNORE INTO source_history VALUES (?,?,?,?)", (record.source, record.source_id, fingerprint, encoded))
                self.db.execute("INSERT OR REPLACE INTO source_latest VALUES (?,?,?)", (record.source, record.source_id, encoded))
                report["changed"] += 1
        return report

    def save_sources(self, records: list[SourceRecord]) -> int:
        return self.save_sources_detailed(records)["changed"]

    def sources(self) -> list[SourceRecord]:
        return [SourceRecord(**json.loads(row[0])) for row in self.db.execute("SELECT payload FROM source_latest ORDER BY source, source_id")]

    def replace_canonical(self, records: list[dict[str, Any]]) -> None:
        # Atomic replacement of derived records; immutable revision history survives.
        with self.db:
            self.db.execute("DELETE FROM canonical")
            for record in records:
                args = (record["vuln_id"], record["revision"], canonical_json(record))
                self.db.execute("INSERT INTO canonical VALUES (?,?,?)", args)
                self.db.execute("INSERT OR IGNORE INTO canonical_history VALUES (?,?,?)", args)
            self.db.execute("DELETE FROM vectors WHERE NOT EXISTS (SELECT 1 FROM canonical c WHERE c.vuln_id=vectors.vuln_id AND c.revision=vectors.revision)")
            self.db.execute("DELETE FROM vector_views WHERE NOT EXISTS (SELECT 1 FROM canonical c WHERE c.vuln_id=vector_views.vuln_id AND c.revision=vector_views.revision)")

    def records(self) -> list[dict[str, Any]]:
        return list(self.iter_records())

    def iter_records(self) -> Iterator[dict[str, Any]]:
        for row in self.db.execute("SELECT payload FROM canonical ORDER BY vuln_id"):
            yield json.loads(row[0])

    def record_count(self) -> int:
        return int(self.db.execute("SELECT count(*) FROM canonical").fetchone()[0])

    def records_page(self, *, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be nonnegative")
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT payload FROM canonical ORDER BY vuln_id LIMIT ? OFFSET ?",
            (limit, offset),
        )]

    def record(self, identifier: str) -> dict[str, Any] | None:
        normalized = identifier.strip().upper()
        if not normalized:
            return None
        row = self.db.execute(
            "SELECT payload FROM canonical WHERE vuln_id=? COLLATE NOCASE",
            (normalized,),
        ).fetchone()
        if row is None:
            row = self.db.execute(
                """SELECT c.payload FROM canonical c, json_each(c.payload, '$.aliases') a
                   WHERE a.value=? COLLATE NOCASE LIMIT 1""",
                (normalized,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_trajectory(self, trajectory: dict[str, Any]) -> dict[str, Any]:
        task_id = trajectory["task_id"]
        steps = trajectory["steps"]
        events = trajectory.get("runtime_events") or []
        environment = trajectory["environment"]
        with self.db:
            self.db.execute(
                """INSERT OR REPLACE INTO security_trajectories
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (task_id, trajectory["schema_version"], trajectory["category"],
                 trajectory["vulnerability_type"], environment["kind"],
                 int(trajectory["success"]), int(trajectory["blocked"]),
                 int(trajectory["is_simulated"]), int(trajectory["execution_ready"]),
                 trajectory["created_at"], trajectory.get("completed_at"), canonical_json(trajectory)),
            )
            self.db.execute("DELETE FROM security_trajectory_steps WHERE task_id=?", (task_id,))
            self.db.execute("DELETE FROM security_runtime_events WHERE task_id=?", (task_id,))
            for index, step in enumerate(steps):
                self.db.execute(
                    "INSERT INTO security_trajectory_steps VALUES (?,?,?,?,?,?)",
                    (task_id, index, step["action_type"], step["tool"], int(step["blocked"]),
                     canonical_json(step)),
                )
            for event in events:
                self.db.execute(
                    """INSERT INTO security_runtime_events
                       (task_id,run_id,timestamp,event_type,payload) VALUES (?,?,?,?,?)""",
                    (task_id, event.get("run_id"), event["timestamp"], event["type"], canonical_json(event)),
                )
        return {"task_id": task_id, "steps": len(steps), "runtime_events": len(events)}

    def trajectory(self, task_id: str) -> dict[str, Any] | None:
        row = self.db.execute(
            "SELECT payload FROM security_trajectories WHERE task_id=?", (task_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def trajectories_page(self, *, limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("limit must be 1..100 and offset nonnegative")
        return [json.loads(row[0]) for row in self.db.execute(
            """SELECT payload FROM security_trajectories
               ORDER BY created_at DESC,task_id LIMIT ? OFFSET ?""", (limit, offset)
        )]

    def trajectory_summary(self) -> dict[str, Any]:
        row = self.db.execute("""SELECT count(*),sum(success),sum(CASE WHEN success=0 THEN 1 ELSE 0 END),
            sum(blocked),sum(is_simulated),sum(CASE WHEN is_simulated=0 THEN 1 ELSE 0 END)
            FROM security_trajectories""").fetchone()
        total = int(row[0] or 0)
        steps = int(self.db.execute("SELECT count(*) FROM security_trajectory_steps").fetchone()[0])
        events = int(self.db.execute("SELECT count(*) FROM security_runtime_events").fetchone()[0])
        abnormal = int(self.db.execute("""SELECT count(*) FROM security_runtime_events
            WHERE event_type IN ('signal','timeout','oom','policy_violation','monitor_lost')""").fetchone()[0])
        categories = {str(item[0]): int(item[1]) for item in self.db.execute(
            "SELECT category,count(*) FROM security_trajectories GROUP BY category ORDER BY category"
        )}
        docker_lab = int(self.db.execute(
            "SELECT count(*) FROM security_trajectories WHERE environment_kind='docker_canary_lab'"
        ).fetchone()[0])
        attested_vm = int(self.db.execute(
            "SELECT count(*) FROM security_trajectories WHERE environment_kind='attested_vm'"
        ).fetchone()[0])
        return {"total": total, "succeeded": int(row[1] or 0), "failed": int(row[2] or 0),
                "blocked": int(row[3] or 0), "simulated": int(row[4] or 0),
                "real_executions": int(row[5] or 0), "steps": steps, "runtime_events": events,
                "abnormal_events": abnormal, "average_steps": (steps / total if total else 0.0),
                "docker_lab_executions": docker_lab, "attested_vm_executions": attested_vm,
                "categories": categories}

    def start_job(self, kind: str) -> int:
        with self.db:
            return self.db.execute("INSERT INTO jobs(kind,status,started_at) VALUES (?, 'running', ?)", (kind, now())).lastrowid

    def end_job(self, job_id: int, status: str, detail: dict[str, Any]) -> None:
        with self.db:
            self.db.execute("UPDATE jobs SET status=?,ended_at=?,detail=? WHERE job_id=?", (status, now(), canonical_json(detail), job_id))

    def sync_cursor(self, source: str, stream: str = "default") -> dict[str, Any] | None:
        row = self.db.execute("SELECT cursor FROM sync_state WHERE source=? AND stream=?", (source, stream)).fetchone()
        return json.loads(row[0]) if row else None

    def save_sync_cursor(self, source: str, cursor: dict[str, Any], stream: str = "default") -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO sync_state VALUES (?,?,?,?)",
                            (source, stream, canonical_json(cursor), now()))

    def record_collection_failure(self, source: str, item_id: str, url: str | None, error: str) -> None:
        timestamp = now()
        with self.db:
            existing = self.db.execute("SELECT attempts,first_seen_at FROM collection_failures WHERE source=? AND item_id=?",
                                       (source, item_id)).fetchone()
            if existing:
                self.db.execute("""UPDATE collection_failures SET url=?,error=?,attempts=?,last_seen_at=?,resolved_at=NULL
                    WHERE source=? AND item_id=?""", (url, error, existing[0] + 1, timestamp, source, item_id))
            else:
                self.db.execute("INSERT INTO collection_failures(source,item_id,url,error,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?)",
                                (source, item_id, url, error, timestamp, timestamp))

    def resolve_collection_failure(self, source: str, item_id: str) -> None:
        with self.db:
            self.db.execute("UPDATE collection_failures SET resolved_at=? WHERE source=? AND item_id=?", (now(), source, item_id))

    def collection_failures(self, *, unresolved_only: bool = True) -> list[dict[str, Any]]:
        where = "WHERE resolved_at IS NULL" if unresolved_only else ""
        return [dict(row) for row in self.db.execute(
            f"SELECT * FROM collection_failures {where} ORDER BY failure_id")]

    def save_poc_artifacts(self, artifacts: list[dict[str, Any]]) -> dict[str, int]:
        """Persist static PoC text, immutable versions and explicit CVE links."""
        import hashlib

        allowed_types = {"detection_template", "exploit_code", "reproduction_code", "scanner_module"}
        allowed_reviews = {"candidate", "static_reviewed", "sandbox_verified", "human_verified", "rejected"}
        report = {"received": len(artifacts), "changed": 0, "unchanged": 0,
                  "versions_added": 0, "links": 0}
        timestamp = now()
        with self.db:
            for artifact in artifacts:
                required = {"artifact_id", "source", "source_item_id", "artifact_type", "title",
                            "source_url", "language", "review_status", "content", "cve_ids"}
                missing = sorted(required - artifact.keys())
                if missing:
                    raise ValueError(f"PoC artifact is missing fields: {', '.join(missing)}")
                if artifact["artifact_type"] not in allowed_types:
                    raise ValueError("Unsupported PoC artifact_type")
                if artifact["review_status"] not in allowed_reviews:
                    raise ValueError("Unsupported PoC review_status")
                content = artifact["content"]
                if not isinstance(content, str) or not content.strip():
                    raise ValueError("PoC content must be non-empty text")
                cve_ids = artifact["cve_ids"]
                if not isinstance(cve_ids, list) or not cve_ids:
                    raise ValueError("PoC artifact must link at least one CVE")
                from .models import CVE_PATTERN
                if any(not isinstance(item, str) or not CVE_PATTERN.fullmatch(item) for item in cve_ids):
                    raise ValueError("PoC links must use canonical CVE identifiers")
                content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
                existing = self.db.execute(
                    "SELECT current_content_sha256 FROM poc_artifacts WHERE artifact_id=?",
                    (artifact["artifact_id"],),
                ).fetchone()
                metadata = canonical_json(artifact.get("metadata") or {})
                values = (
                    artifact["artifact_id"], artifact["source"], artifact["source_item_id"],
                    artifact["artifact_type"], artifact["title"], artifact["source_url"],
                    artifact.get("commit_ref"), artifact.get("local_path"), artifact["language"],
                    artifact.get("license"), artifact["review_status"], content_sha256,
                    timestamp, timestamp, metadata,
                )
                self.db.execute("""
                    INSERT INTO poc_artifacts(
                        artifact_id,source,source_item_id,artifact_type,title,source_url,commit_ref,
                        local_path,language,license,review_status,current_content_sha256,
                        first_seen_at,last_seen_at,metadata)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(artifact_id) DO UPDATE SET
                        artifact_type=excluded.artifact_type,title=excluded.title,
                        source_url=excluded.source_url,commit_ref=excluded.commit_ref,
                        local_path=excluded.local_path,language=excluded.language,
                        license=excluded.license,current_content_sha256=excluded.current_content_sha256,
                        last_seen_at=excluded.last_seen_at,metadata=excluded.metadata
                """, values)
                before = self.db.total_changes
                self.db.execute(
                    "INSERT OR IGNORE INTO poc_artifact_versions VALUES (?,?,?,?,?)",
                    (artifact["artifact_id"], content_sha256, content, len(content.encode("utf-8")), timestamp),
                )
                version_added = self.db.total_changes > before
                if version_added:
                    report["versions_added"] += 1
                if existing and existing[0] == content_sha256:
                    report["unchanged"] += 1
                else:
                    report["changed"] += 1
                self.db.execute("DELETE FROM poc_vulnerability_links WHERE artifact_id=?", (artifact["artifact_id"],))
                relation = str(artifact.get("link_relation") or "associated")
                confidence = float(artifact.get("link_confidence", 0.5))
                if not 0 <= confidence <= 1:
                    raise ValueError("PoC link confidence must be between 0 and 1")
                for cve_id in sorted(set(cve_ids)):
                    evidence = canonical_json({"source": artifact["source"],
                                               "source_item_id": artifact["source_item_id"],
                                               "content_sha256": content_sha256})
                    self.db.execute(
                        "INSERT INTO poc_vulnerability_links VALUES (?,?,?,?,?)",
                        (artifact["artifact_id"], cve_id.upper(), relation, confidence, evidence),
                    )
                    report["links"] += 1
        return report

    def poc_status(self) -> dict[str, Any]:
        scalar = lambda sql: self.db.execute(sql).fetchone()[0]
        return {
            "artifacts": scalar("SELECT COUNT(*) FROM poc_artifacts"),
            "versions": scalar("SELECT COUNT(*) FROM poc_artifact_versions"),
            "links": scalar("SELECT COUNT(*) FROM poc_vulnerability_links"),
            "unique_cves": scalar("SELECT COUNT(DISTINCT vuln_id) FROM poc_vulnerability_links"),
            "linked_canonical_cves": scalar("""SELECT COUNT(DISTINCT l.vuln_id)
                FROM poc_vulnerability_links l JOIN canonical c ON c.vuln_id=l.vuln_id"""),
            "content_bytes": scalar("SELECT COALESCE(SUM(content_size),0) FROM poc_artifact_versions"),
            "by_source": {row[0]: row[1] for row in self.db.execute(
                "SELECT source,COUNT(*) FROM poc_artifacts GROUP BY source ORDER BY source")},
            "by_type": {row[0]: row[1] for row in self.db.execute(
                "SELECT artifact_type,COUNT(*) FROM poc_artifacts GROUP BY artifact_type ORDER BY artifact_type")},
            "by_review_status": {row[0]: row[1] for row in self.db.execute(
                "SELECT review_status,COUNT(*) FROM poc_artifacts GROUP BY review_status ORDER BY review_status")},
        }
