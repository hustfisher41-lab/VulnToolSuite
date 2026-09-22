"""Evidence-backed missing-field enrichment using explicitly selected sources."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any, Callable
import math

from .collection import fetch_record
from .models import CVE_PATTERN, FIELDS, SourceRecord
from .processing import process
from .storage import Store


def _missing(record: dict[str, Any]) -> list[str]:
    return [name for name in FIELDS if record.get("field_states", {}).get(name) == "missing"]


def enrich_missing(
    store: Store,
    *,
    sources: list[str] | None = None,
    api_key: str | None = None,
    url_templates: dict[str, str] | None = None,
    authorized_configs: dict[str, str | Path] | None = None,
    max_records: int = 100,
    max_requests: int = 200,
    apply: bool = True,
    fetcher: Callable[..., SourceRecord] = fetch_record,
) -> dict[str, Any]:
    """Fetch source records, prove which fields improve, then atomically reprocess."""
    selected = sources or ["cve", "nvd"]
    if not selected or any(source not in {"cve", "nvd", "avd", "cnnvd"} for source in selected):
        raise ValueError("sources must contain cve, nvd, avd, or cnnvd")
    if len(set(selected)) != len(selected):
        raise ValueError("sources cannot contain duplicates")
    if type(max_records) is not int or max_records < 1:
        raise ValueError("max_records must be a positive integer")
    if type(max_requests) is not int or max_requests < 1:
        raise ValueError("max_requests must be a positive integer")
    templates = url_templates or {}
    configs = authorized_configs or {}
    if set(configs) - {"avd", "cnnvd"}:
        raise ValueError("Authorized API configs only apply to avd or cnnvd")
    current_sources = store.sources()
    before_records = process(current_sources)
    targets = [record for record in before_records if record["status"] == "active" and _missing(record)][:max_records]
    attempts, candidates, errors = [], [], []
    request_count = 0
    for target in targets:
        if not CVE_PATTERN.fullmatch(target["vuln_id"]):
            errors.append({"vuln_id": target["vuln_id"], "kind": "no_cve_identity", "missing_fields": _missing(target)})
            continue
        for source in selected:
            if request_count >= max_requests:
                break
            request_count += 1
            try:
                candidate = fetcher(source, target["vuln_id"], api_key=api_key, url_template=templates.get(source),
                                    authorized_config=configs.get(source))
                candidates.append(candidate)
                attempts.append({
                    "vuln_id": target["vuln_id"], "source": source, "source_id": candidate.source_id,
                    "url": candidate.url, "status": "fetched",
                })
            except Exception as exc:
                item = {"vuln_id": target["vuln_id"], "source": source, "status": "failed", "error": str(exc)}
                attempts.append(item)
                errors.append({**item, "kind": "source_fetch_failed"})
                if apply:
                    store.record_collection_failure(source, target["vuln_id"], templates.get(source), str(exc))
        if request_count >= max_requests:
            break

    candidate_records = process([*current_sources, *candidates])
    candidate_by_id = {record["vuln_id"]: record for record in candidate_records}
    improvements = []
    for before in targets:
        after = candidate_by_id.get(before["vuln_id"], before)
        filled = [field for field in _missing(before) if after.get("field_states", {}).get(field) != "missing"]
        changed_to_conflict = [field for field in FIELDS if before.get("field_states", {}).get(field) != "conflicted" and after.get("field_states", {}).get(field) == "conflicted"]
        improvements.append({
            "vuln_id": before["vuln_id"], "missing_before": _missing(before),
            "filled_fields": filled, "new_conflicts": changed_to_conflict,
            "missing_after": _missing(after),
        })
    save_report = None
    if apply and candidates:
        save_report = store.save_sources_detailed(candidates)
        store.replace_canonical(process(store.sources()))
        for candidate in candidates:
            store.resolve_collection_failure(candidate.source, candidate.vuln_id)
    return {
        "schema": "vulntools/enrichment/v1", "mode": "apply" if apply else "dry_run",
        "sources": selected, "targets": len(targets), "requests": request_count,
        "attempts": attempts, "improvements": improvements, "errors": errors,
        "saved": save_report,
        "limits": {"max_records": max_records, "max_requests": max_requests},
        "policy": "Only parsed source records with provenance are eligible; search snippets never populate fields.",
    }


def attach_ocr_artifact(
    store: Store,
    source: str,
    source_id: str,
    artifact_path: str | Path,
    *,
    replace_existing: bool = False,
) -> dict[str, Any]:
    """Attach reviewed OCR text to one source record and rebuild aligned evidence."""
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8-sig"))
    if artifact.get("schema_version") != "vulntools/v1" or artifact.get("modality") != "image":
        raise ValueError("OCR artifact must use the vulntools/v1 image contract")
    if not isinstance(artifact.get("content_hash"), str) or len(artifact["content_hash"]) != 64:
        raise ValueError("OCR artifact requires a SHA-256 content_hash")
    text = artifact.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("OCR artifact contains no extracted text")
    matches = [record for record in store.sources() if record.source == source and record.source_id.casefold() == source_id.casefold()]
    if len(matches) != 1:
        raise ValueError("Exactly one matching source record is required")
    current = matches[0]
    if current.fields.get("image_text") and current.fields["image_text"] != text and not replace_existing:
        raise ValueError("Source already has different image_text; use replace_existing after review")
    raw = dict(current.raw)
    artifacts = list(raw.get("_vulntools_ocr_artifacts", []))
    summary = {key: artifact.get(key) for key in ("content_hash", "extractor", "language", "path")}
    if summary not in artifacts:
        artifacts.append(summary)
    raw["_vulntools_ocr_artifacts"] = artifacts
    fields = dict(current.fields)
    fields["image_text"] = text
    updated = replace(current, raw=raw, fields=fields)
    saved = store.save_sources_detailed([updated])
    records = process(store.sources())
    store.replace_canonical(records)
    return {
        "source": source, "source_id": source_id, "vuln_id": updated.vuln_id,
        "content_hash": artifact["content_hash"], "characters": len(text),
        "saved": saved, "canonical_revision": next(record["revision"] for record in records if record["vuln_id"] == updated.vuln_id),
    }


def attach_vision_artifact(store: Store, source: str, source_id: str,
                           artifact_path: str | Path) -> dict[str, Any]:
    """Attach a local native-image embedding without treating it as OCR text."""
    from .models import digest
    from .vision import VISION_SCHEMA

    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8-sig"))
    if artifact.get("schema") != VISION_SCHEMA or artifact.get("modality") != "image_embedding":
        raise ValueError(f"Vision artifact must use {VISION_SCHEMA}")
    vector = artifact.get("embedding")
    dimension = artifact.get("dimension")
    if not isinstance(dimension, int) or dimension < 1 or not isinstance(vector, list) or len(vector) != dimension:
        raise ValueError("Vision artifact has an invalid embedding dimension")
    if any(type(value) not in {int, float} or not math.isfinite(float(value)) for value in vector):
        raise ValueError("Vision artifact embedding must contain finite numbers")
    if artifact.get("embedding_hash") != digest([float(value) for value in vector]):
        raise ValueError("Vision artifact embedding hash does not match its vector")
    model = artifact.get("model")
    if not isinstance(model, dict) or model.get("modality") != "image" or not model.get("native_vision_model"):
        raise ValueError("Vision artifact model does not declare native image support")
    if artifact.get("model_id") != digest(model):
        raise ValueError("Vision artifact model_id does not match its manifest")
    content_hash = artifact.get("content_hash")
    if not isinstance(content_hash, str) or not re_full_sha256(content_hash):
        raise ValueError("Vision artifact requires a SHA-256 content_hash")
    matches = [record for record in store.sources()
               if record.source == source and record.source_id.casefold() == source_id.casefold()]
    if len(matches) != 1:
        raise ValueError("Exactly one matching source record is required")
    current = matches[0]
    fields = dict(current.fields)
    artifacts = list(fields.get("image_embeddings") or [])
    key = (content_hash, artifact["model_id"])
    existing = next((item for item in artifacts
                     if (item.get("content_hash"), item.get("model_id")) == key), None)
    if existing and existing.get("embedding_hash") != artifact["embedding_hash"]:
        raise ValueError("A different embedding already exists for this image and model")
    if existing is None:
        artifacts.append({key: artifact[key] for key in (
            "content_hash", "model_id", "model", "dimension", "embedding_hash", "embedding", "path")})
    fields["image_embeddings"] = artifacts
    raw = dict(current.raw)
    raw["_vulntools_vision_artifacts"] = [
        {key: item.get(key) for key in ("content_hash", "model_id", "dimension", "embedding_hash", "path")}
        for item in artifacts
    ]
    updated = replace(current, raw=raw, fields=fields)
    saved = store.save_sources_detailed([updated])
    records = process(store.sources())
    store.replace_canonical(records)
    canonical = next(record for record in records if record["vuln_id"] == updated.vuln_id)
    return {
        "source": source, "source_id": source_id, "vuln_id": updated.vuln_id,
        "content_hash": content_hash, "model_id": artifact["model_id"], "dimension": dimension,
        "saved": saved, "canonical_revision": canonical["revision"],
    }


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdefABCDEF" for character in value)
