"""Build source-grounded JSONL for SFT/RAG and quarantined preference review."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any, TextIO

from .models import canonical_json, digest, now
from .storage import Store


TRAINING_SCHEMA = "vulntools/training-dataset/v2"


def _split(family_id: str, seed: str) -> str:
    bucket = int(hashlib.sha256(f"{seed}:{family_id}".encode("utf-8")).hexdigest()[:8], 16) % 100
    return "train" if bucket < 80 else "validation" if bucket < 90 else "test"


def _text_hash(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _write(handle: TextIO, row: dict[str, Any]) -> None:
    handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")


def _chunks(text: str, size: int, overlap: int) -> list[str]:
    if len(text) <= size:
        return [text]
    chunks, start = [], 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            newline = text.rfind("\n", start + size // 2, end)
            if newline > start:
                end = newline + 1
        chunk = text[start:end]
        if chunk.strip():
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(start + 1, end - overlap)
    return chunks


class _Families:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, value: str) -> str:
        root = self.parent.setdefault(value, value)
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[value] != value:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def union(self, left: str, right: str) -> None:
        a, b = self.find(left), self.find(right)
        if a != b:
            low, high = sorted((a, b))
            self.parent[high] = low


def _artifact_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {key: item.get(key) for key in (
        "artifact_id", "source", "source_item_id", "artifact_type", "title", "source_url",
        "commit_ref", "language", "license", "review_status", "content_sha256", "relation", "confidence",
    )}


def _sample_id(kind: str, *parts: Any) -> str:
    return f"{kind}-{digest([kind, *parts])[:24]}"


def _primary_component(fields: dict[str, Any]) -> str:
    for item in fields.get("components") or []:
        if not isinstance(item, dict):
            continue
        vendor, name = str(item.get("vendor") or "").strip(), str(item.get("name") or "").strip()
        if name and name.casefold() != "n/a":
            return f"{vendor}/{name}".casefold()
    return ""


def _clean_components(components: Any) -> list[dict[str, Any]]:
    """Exclude source placeholders from supervised labels, not from raw evidence."""
    if not isinstance(components, list):
        return []
    result = []
    for item in components:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if name.casefold() in {"", "n/a", "na", "unknown", "not applicable", "unspecified", "*"}:
            continue
        result.append({key: item[key] for key in ("vendor", "name", "versions", "cpes", "purls") if key in item})
    return result


def _grounded_fields(record: dict[str, Any]) -> dict[str, Any]:
    fields = record.get("fields") or {}
    states = record.get("field_states") or {}
    conflicts = record.get("conflicts") or {}
    def available(key: str) -> Any:
        return None if states.get(key) in {"missing", "conflicted"} or key in conflicts else fields.get(key)
    severity = str(available("severity") or "").lower()
    return {"vuln_id": record["vuln_id"],
            "severity": severity if severity in {"critical", "high", "medium", "low", "none"} else None,
            "weaknesses": [value for value in available("weaknesses") or []
                           if isinstance(value, str) and re.fullmatch(r"CWE-\d+", value)],
            "components": _clean_components(available("components"))}


def _pick_other(candidates: list[str], current: str, salt: str) -> str | None:
    if len(candidates) < 2:
        return None
    start = int(hashlib.sha256(f"{salt}:{current}".encode()).hexdigest()[:8], 16) % len(candidates)
    for offset in range(len(candidates)):
        candidate = candidates[(start + offset) % len(candidates)]
        if candidate != current:
            return candidate
    return None


def build_training_dataset(
    store: Store,
    output: str | Path,
    *,
    max_records: int | None = None,
    min_description_chars: int = 40,
    chunk_chars: int = 4000,
    chunk_overlap: int = 200,
    max_code_chars: int = 200_000,
    split_seed: str = "vulntools-v1",
    include_code: bool = True,
) -> dict[str, Any]:
    """Create leakage-aware knowledge/SFT/RAG and review-only preference candidates."""
    if max_records is not None and max_records < 1:
        raise ValueError("max_records must be positive")
    if min_description_chars < 1:
        raise ValueError("min_description_chars must be positive")
    if chunk_chars < 256 or not 0 <= chunk_overlap < chunk_chars:
        raise ValueError("chunk_chars must be >=256 and overlap must be smaller")
    if max_code_chars < chunk_chars:
        raise ValueError("max_code_chars must be at least chunk_chars")

    target = Path(output)
    target.mkdir(parents=True, exist_ok=True)
    paths = {name: target / name for name in (
        "knowledge.jsonl", "sft.jsonl", "preference.jsonl", "preference-candidates.jsonl", "rag-corpus.jsonl",
        "retrieval.jsonl", "dataset-manifest.jsonl",
    )}
    temp_paths = {name: path.with_suffix(path.suffix + ".tmp") for name, path in paths.items()}

    artifact_cves: dict[str, list[str]] = defaultdict(list)
    artifact_meta: dict[str, dict[str, Any]] = {}
    artifacts_by_vuln: dict[str, list[dict[str, Any]]] = defaultdict(list)
    families = _Families()
    for row in store.db.execute("""
        SELECT a.artifact_id,a.source,a.source_item_id,a.artifact_type,a.title,a.source_url,
               a.commit_ref,a.language,a.license,a.review_status,a.current_content_sha256,
               l.vuln_id,l.relation,l.confidence
        FROM poc_artifacts a JOIN poc_vulnerability_links l ON l.artifact_id=a.artifact_id
        WHERE a.review_status != 'rejected'
        ORDER BY a.artifact_id,l.vuln_id
    """):
        item = {
            "artifact_id": row[0], "source": row[1], "source_item_id": row[2],
            "artifact_type": row[3], "title": row[4], "source_url": row[5],
            "commit_ref": row[6], "language": row[7], "license": row[8],
            "review_status": row[9], "content_sha256": row[10], "vuln_id": row[11],
            "relation": row[12], "confidence": row[13],
        }
        artifact_meta.setdefault(row[0], item)
        artifact_cves[row[0]].append(row[11])
        artifacts_by_vuln[row[11]].append(item)
    for cves in artifact_cves.values():
        for cve in cves[1:]:
            families.union(cves[0], cve)

    # Duplicate content in different repositories must not escape family grouping.
    content_groups: dict[str, list[str]] = defaultdict(list)
    content_artifacts: dict[str, list[str]] = defaultdict(list)
    chunk_owners: dict[str, str] = {}
    for row in store.db.execute("""SELECT a.artifact_id,v.content FROM poc_artifacts a
        JOIN poc_artifact_versions v ON v.artifact_id=a.artifact_id
          AND v.content_sha256=a.current_content_sha256 WHERE a.review_status != 'rejected'
        ORDER BY a.artifact_id"""):
        linked = artifact_cves.get(row[0], [])
        content_key = _text_hash(row[1])
        content_groups[content_key].extend(linked)
        content_artifacts[content_key].append(row[0])
        if include_code and linked and len(row[1]) <= max_code_chars:
            for chunk in _chunks(row[1], chunk_chars, chunk_overlap):
                previous = chunk_owners.setdefault(_text_hash(chunk), linked[0])
                families.union(previous, linked[0])
    for cves in content_groups.values():
        for cve in cves[1:]:
            families.union(cves[0], cve)
    description_owners: dict[str, str] = {}
    for row in store.db.execute("SELECT payload FROM canonical ORDER BY vuln_id"):
        record = json.loads(row[0])
        if record.get("status") != "active":
            continue
        description = str((record.get("fields") or {}).get("description") or "").strip()
        if len(description) >= min_description_chars:
            key = _text_hash(description)
            previous = description_owners.setdefault(key, record["vuln_id"])
            families.union(previous, record["vuln_id"])

    counts = Counter()
    filters = Counter()
    split_counts = Counter()
    sample_hashes: set[str] = set()
    code_hash_to_docs: dict[str, list[str]] = {}
    code_docs_by_vuln: dict[str, list[str]] = defaultdict(list)
    record_info: dict[str, dict[str, Any]] = {}
    description_docs: dict[str, str] = {}
    doc_splits: dict[str, str] = {}
    missing_doc_references = 0
    cross_split_doc_references = 0
    manifest_rows: list[dict[str, Any]] = []
    source_fingerprint = hashlib.sha256()

    handles = {name: path.open("w", encoding="utf-8", newline="\n") for name, path in temp_paths.items()}
    try:
        seen_records = 0
        for db_row in store.db.execute("SELECT payload FROM canonical ORDER BY vuln_id"):
            if max_records is not None and seen_records >= max_records:
                break
            record = json.loads(db_row[0])
            if record.get("status") != "active":
                filters["inactive"] += 1
                continue
            seen_records += 1
            vuln_id = record["vuln_id"]
            fields = record.get("fields") or {}
            description = str(fields.get("description") or "").strip()
            if len(description) < min_description_chars:
                filters["short_or_missing_description"] += 1
                continue
            family_id = families.find(vuln_id)
            split = _split(family_id, split_seed)
            split_counts[split] += 1
            target_fields = _grounded_fields(record)
            weaknesses = target_fields["weaknesses"]
            severity = target_fields["severity"] or "unknown"
            components = target_fields["components"]
            pocs = [_artifact_summary(item) for item in artifacts_by_vuln.get(vuln_id, [])]
            source_fingerprint.update(f"{vuln_id}:{record['revision']}\n".encode())

            knowledge_id = _sample_id("knowledge", vuln_id, record["revision"])
            knowledge = {
                "schema": TRAINING_SCHEMA, "sample_id": knowledge_id, "task_family": "knowledge_injection",
                "vuln_id": vuln_id, "family_id": family_id, "split": split,
                "knowledge": {
                    "aliases": record.get("aliases") or [], "title": fields.get("title"),
                    "description": description, "severity": fields.get("severity"), "cvss": fields.get("cvss"),
                    "weaknesses": weaknesses, "components": components,
                    "attack_preconditions": fields.get("attack_preconditions"),
                    "patch": fields.get("patch"), "references": record.get("references") or [],
                    "poc_artifacts": pocs,
                },
                "provenance": {"revision": record["revision"], "sources": record.get("sources") or [],
                               "fields": record.get("provenance") or {}},
                "quality": {"field_states": record.get("field_states") or {},
                            "conflicted_fields": sorted((record.get("conflicts") or {}).keys()),
                            "poc_review_statuses": sorted({item.get("review_status") for item in pocs}),
                            "license_review_required": any(not item.get("license") for item in pocs)},
            }
            _write(handles["knowledge.jsonl"], knowledge)
            counts["knowledge"] += 1

            desc_doc = _sample_id("doc-description", vuln_id, record["revision"])
            description_docs[vuln_id] = desc_doc
            doc_splits[desc_doc] = split
            _write(handles["rag-corpus.jsonl"], {
                "schema": TRAINING_SCHEMA, "doc_id": desc_doc, "vuln_ids": [vuln_id],
                "family_id": family_id, "split": split, "modality": "description",
                "title": fields.get("title") or vuln_id, "text": description,
                "content_sha256": _text_hash(description),
                "metadata": {"severity": fields.get("severity"), "weaknesses": weaknesses,
                             "components": components, "revision": record["revision"]},
            })
            counts["rag_description_docs"] += 1

            labels = [*weaknesses, *([f"severity:{severity}"] if severity != "unknown" else [])]
            if not weaknesses and severity == "unknown" and not components:
                filters["classification_without_labels"] += 1
            else:
                messages = [
                    {"role": "system", "content": "你是漏洞知识抽取助手。仅依据输入证据输出JSON；未知字段使用null或空数组，不编造事实，不输出隐藏推理过程。"},
                    {"role": "user", "content": "根据以下结构化来源证据整理CVE、严重性、CWE和受影响产品，未知保持为空：\n" + canonical_json({
                        "description": description, "source_assertions": target_fields,
                        "field_states": record.get("field_states") or {},
                        "sources": record.get("sources") or []})},
                    {"role": "assistant", "content": canonical_json(target_fields)},
                ]
                sample_hash = digest(messages)
                if sample_hash not in sample_hashes:
                    sample_hashes.add(sample_hash)
                    sample_id = _sample_id("sft-classification", vuln_id, record["revision"])
                    _write(handles["sft.jsonl"], {"schema": TRAINING_SCHEMA, "sample_id": sample_id,
                           "task": "grounded_metadata_extraction", "vuln_id": vuln_id,
                           "family_id": family_id, "split": split, "messages": messages,
                           "labels": labels, "label_origin": "canonical_source_assertions",
                           "is_classification_benchmark": False})
                    manifest_rows.append({"sample_id": sample_id, "vuln_id": vuln_id,
                                          "family_id": family_id, "split": split,
                                          "labels": labels, "modalities": ["text", "metadata"], "weight": 1.0})
                    counts["sft_classification"] += 1
                else:
                    filters["duplicate_sft"] += 1

            if pocs:
                poc = pocs[0]
                messages = [
                    {"role": "system", "content": "你是漏洞与PoC关联审核助手。仅根据给定证据返回JSON结论，不执行代码，不补充未提供事实。"},
                    {"role": "user", "content": "整理上游关联声明，区分声明与实际复现验证。\n漏洞：" + canonical_json({"vuln_id": vuln_id, "description": description}) + "\n上游关联证据：" + canonical_json({"claimed_vuln_id": vuln_id, "artifact": poc})},
                    {"role": "assistant", "content": canonical_json({"upstream_claimed_association": True,
                                                                       "replay_verified": poc["review_status"] == "sandbox_verified",
                                                                       "vuln_id": vuln_id,
                                                                       "artifact_id": poc["artifact_id"],
                                                                       "relation": poc["relation"],
                                                                       "confidence": poc["confidence"],
                                                                       "verification_status": poc["review_status"]})},
                ]
                sample_id = _sample_id("sft-poc", vuln_id, poc["artifact_id"])
                _write(handles["sft.jsonl"], {"schema": TRAINING_SCHEMA, "sample_id": sample_id,
                       "task": "poc_claim_extraction", "vuln_id": vuln_id, "family_id": family_id,
                       "split": split, "messages": messages,
                       "labels": [poc["artifact_type"], poc["source"]],
                       "label_origin": "upstream_cve_claim_not_replay_ground_truth"})
                manifest_rows.append({"sample_id": sample_id, "vuln_id": vuln_id,
                                      "family_id": family_id, "split": split,
                                      "labels": [poc["artifact_type"], poc["source"]],
                                      "modalities": ["text", "code_metadata"], "weight": 0.75})
                counts["sft_poc_association"] += 1

            record_info[vuln_id] = {"family_id": family_id, "split": split,
                                    "weaknesses": weaknesses, "severity": severity,
                                    "component": _primary_component({"components": components}),
                                    "description": description, "description_hash": _text_hash(description),
                                    "query": f"{vuln_id} 漏洞说明、影响产品及检测证据"}

        if include_code:
            for row in store.db.execute("""
                SELECT a.artifact_id,a.source,a.source_item_id,a.artifact_type,a.title,a.language,
                       a.review_status,a.current_content_sha256,v.content
                FROM poc_artifacts a JOIN poc_artifact_versions v
                  ON v.artifact_id=a.artifact_id AND v.content_sha256=a.current_content_sha256
                WHERE a.review_status != 'rejected' ORDER BY a.artifact_id
            """):
                cves = sorted({cve for cve in artifact_cves.get(row[0], []) if cve in record_info})
                if not cves:
                    filters["poc_without_selected_canonical"] += 1
                    continue
                content = row[8]
                if len(content) > max_code_chars:
                    filters["code_too_long"] += 1
                    continue
                content_hash = _text_hash(content)
                if content_hash in code_hash_to_docs:
                    filters["duplicate_poc_content"] += 1
                    for cve in cves:
                        code_docs_by_vuln[cve].extend(code_hash_to_docs[content_hash])
                    continue
                cves = sorted({cve for cve in content_groups[content_hash] if cve in record_info})
                provenance = [_artifact_summary(artifact_meta[artifact_id])
                              for artifact_id in content_artifacts[content_hash] if artifact_id in artifact_meta]
                chunks = _chunks(content, chunk_chars, chunk_overlap)
                artifact_doc_ids = []
                for index, chunk in enumerate(chunks):
                    doc_id = _sample_id("doc-poc", row[0], content_hash, index)
                    artifact_doc_ids.append(doc_id)
                    doc_splits[doc_id] = record_info[cves[0]]["split"]
                    _write(handles["rag-corpus.jsonl"], {
                        "schema": TRAINING_SCHEMA, "doc_id": doc_id, "vuln_ids": cves,
                        "family_id": record_info[cves[0]]["family_id"],
                        "split": record_info[cves[0]]["split"], "modality": "poc_code",
                        "title": row[4], "text": chunk, "content_sha256": _text_hash(chunk),
                        "metadata": {"artifact_id": row[0], "source": row[1], "source_item_id": row[2],
                                     "artifact_type": row[3], "language": row[5],
                                     "review_status": row[6], "artifact_content_sha256": row[7],
                                     "normalized_content_sha256": content_hash,
                                     "source_provenance": provenance,
                                     "requires_human_review": row[6] == "candidate",
                                     "license_review_required": any(not item.get("license") for item in provenance),
                                     "chunk_index": index, "chunk_count": len(chunks)},
                    })
                    counts["rag_poc_code_docs"] += 1
                    for cve in cves:
                        code_docs_by_vuln[cve].append(doc_id)
                code_hash_to_docs[content_hash] = artifact_doc_ids

        groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for vuln_id, info in record_info.items():
            for weakness in info["weaknesses"]:
                groups[(info["split"], "weakness", weakness)].append(vuln_id)
            if info["component"]:
                groups[(info["split"], "component", info["component"])].append(vuln_id)
            if info["severity"] != "unknown":
                groups[(info["split"], "severity", info["severity"])].append(vuln_id)
        for values in groups.values():
            values.sort()

        for vuln_id, info in record_info.items():
            negative = None
            strategies = [
                ("weakness", [groups[(info["split"], "weakness", value)] for value in info["weaknesses"]]),
                ("component", [groups[(info["split"], "component", info["component"])]] if info["component"] else []),
                ("severity", [groups[(info["split"], "severity", info["severity"])]] if info["severity"] != "unknown" else [])
            ]
            for kind, values in strategies:
                for candidates in values:
                    start = int(hashlib.sha256(f"retrieval:{kind}:{vuln_id}".encode()).hexdigest()[:8], 16) % max(1, len(candidates))
                    negative = next((candidate for offset in range(len(candidates))
                                     for candidate in [candidates[(start + offset) % len(candidates)]]
                                     if record_info[candidate]["family_id"] != info["family_id"]), None)
                    if negative:
                        break
                if negative:
                    break
            positives = [description_docs[vuln_id], *sorted(set(code_docs_by_vuln.get(vuln_id, [])))]
            hard_negatives = [description_docs[negative]] if negative else []
            for doc_id in [*positives, *hard_negatives]:
                if doc_id not in doc_splits:
                    missing_doc_references += 1
                elif doc_splits[doc_id] != info["split"]:
                    cross_split_doc_references += 1
            sample_id = _sample_id("retrieval", vuln_id, info["family_id"])
            _write(handles["retrieval.jsonl"], {
                "schema": TRAINING_SCHEMA, "sample_id": sample_id, "vuln_id": vuln_id,
                "family_id": info["family_id"], "split": info["split"],
                "query": info["query"], "query_origin": "templated_cve_lookup_not_semantic_benchmark",
                "positive_doc_ids": positives,
                "hard_negative_doc_ids": hard_negatives,
                "negative_strategy": "same_weakness_then_component_then_severity",
                "negative_is_verified": False, "requires_human_review": bool(negative),
            })
            manifest_rows.append({"sample_id": sample_id, "vuln_id": vuln_id,
                                  "family_id": info["family_id"], "split": info["split"],
                                  "labels": info["weaknesses"], "modalities": ["retrieval"], "weight": 1.0})
            counts["retrieval"] += 1
            if negative:
                counts["hard_negatives"] += 1
            else:
                filters["no_hard_negative"] += 1

        artifact_groups: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for artifact_id, item in artifact_meta.items():
            selected = [cve for cve in artifact_cves[artifact_id] if cve in record_info]
            if selected:
                split = record_info[selected[0]]["split"]
                artifact_groups[(split, item["artifact_type"], item["language"])].append(artifact_id)
        for values in artifact_groups.values():
            values.sort()
        for vuln_id, info in record_info.items():
            positives = artifacts_by_vuln.get(vuln_id) or []
            if not positives:
                continue
            positive = positives[0]
            candidates = artifact_groups[(info["split"], positive["artifact_type"], positive["language"])]
            start = int(hashlib.sha256(f"preference:{vuln_id}".encode()).hexdigest()[:8], 16) % max(1, len(candidates))
            negative_id = next((candidate for offset in range(len(candidates))
                                for candidate in [candidates[(start + offset) % len(candidates)]]
                                if candidate != positive["artifact_id"]
                                and all(families.find(cve) != info["family_id"] for cve in artifact_cves[candidate])), None)
            if not negative_id:
                filters["no_preference_hard_negative"] += 1
                continue
            pos, neg = _artifact_summary(positive), _artifact_summary(artifact_meta[negative_id])
            prompt = "为漏洞选择更匹配的PoC候选。漏洞：" + canonical_json({"vuln_id": vuln_id, "description": info["description"]}) + "\n候选：" + canonical_json([pos, neg])
            sample_id = _sample_id("preference", vuln_id, pos["artifact_id"], neg["artifact_id"])
            _write(handles["preference-candidates.jsonl"], {
                "schema": TRAINING_SCHEMA, "sample_id": sample_id, "task": "poc_association_preference",
                "vuln_id": vuln_id, "family_id": info["family_id"], "split": info["split"],
                "prompt": prompt,
                "chosen": canonical_json({"artifact_id": pos["artifact_id"], "associated": True}),
                "rejected": canonical_json({"artifact_id": neg["artifact_id"], "associated": True}),
                "preference_origin": "synthetic_hard_negative_same_type_language",
                "requires_human_review": True,
                "training_eligible": False,
                "reason": "Absence of an upstream CVE link is not proof of a negative association.",
            })
            # Review candidates must not enter the formal training sample manifest.
            counts["preference_candidates"] += 1

        for row in manifest_rows:
            _write(handles["dataset-manifest.jsonl"], row)
        counts["manifest_rows"] = len(manifest_rows)
        counts["preference"] = 0
    finally:
        for handle in handles.values():
            handle.close()

    # Do not publish a package known to contain unresolved or cross-split references.
    if missing_doc_references or cross_split_doc_references:
        raise ValueError("Training dataset has missing or cross-split document references; temporary files were not published")
    for name, path in paths.items():
        temp_paths[name].replace(path)

    artifacts = {}
    for name, path in paths.items():
        file_hash = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
                file_hash.update(block)
        with path.open("r", encoding="utf-8") as handle:
            row_count = sum(1 for _ in handle)
        artifacts[name] = {"path": str(path.resolve()), "bytes": path.stat().st_size,
                           "sha256": file_hash.hexdigest(), "rows": row_count}

    dataset_id = digest({"source": source_fingerprint.hexdigest(), "parameters": {
        "min_description_chars": min_description_chars, "chunk_chars": chunk_chars,
        "chunk_overlap": chunk_overlap, "max_code_chars": max_code_chars,
        "split_seed": split_seed, "include_code": include_code},
        "artifacts": {name: {key: value for key, value in item.items() if key != "path"}
                      for name, item in artifacts.items()}})
    sample_id_counts = Counter(row["sample_id"] for row in manifest_rows)
    vuln_splits: dict[str, set[str]] = defaultdict(set)
    family_splits: dict[str, set[str]] = defaultdict(set)
    for row in manifest_rows:
        vuln_splits[row["vuln_id"]].add(row["split"])
        family_splits[row["family_id"]].add(row["split"])
    validation = {
        "status": "passed" if (
            all(count == 1 for count in sample_id_counts.values())
            and all(len(values) == 1 for values in vuln_splits.values())
            and all(len(values) == 1 for values in family_splits.values())
            and missing_doc_references == 0
            and cross_split_doc_references == 0
        ) else "failed",
        "duplicate_sample_ids": sum(count > 1 for count in sample_id_counts.values()),
        "vulnerability_split_leakage": sum(len(values) > 1 for values in vuln_splits.values()),
        "family_split_leakage": sum(len(values) > 1 for values in family_splits.values()),
        "missing_doc_references": missing_doc_references,
        "cross_split_doc_references": cross_split_doc_references,
        "known_vulnerabilities": len(record_info),
        "description_documents": len(description_docs),
        "unique_poc_code_contents": len(code_hash_to_docs),
        "note": "Synthetic preference pairs remain subject to human review even when structural validation passes.",
    }
    report = {
        "schema": TRAINING_SCHEMA, "dataset_id": dataset_id, "created_at": now(),
        "counts": dict(counts), "filters": dict(filters), "splits": dict(split_counts),
        "parameters": {"max_records": max_records, "min_description_chars": min_description_chars,
                       "chunk_chars": chunk_chars, "chunk_overlap": chunk_overlap,
                       "max_code_chars": max_code_chars, "split_seed": split_seed,
                       "include_code": include_code},
        "quality": {"split_unit": "poc_and_duplicate_content_connected_cve_family",
                    "duplicate_code_chunks": "grouped into same split",
                    "exact_dedup": "normalized PoC content; duplicate descriptions grouped into same split",
                    "hard_negative_strategy": "same_weakness_then_component_then_severity",
                    "preference_origin": "synthetic; requires human review",
                    "chain_of_thought": "not_generated", "poc_execution": "never"},
        "task_coverage": {"grounded_metadata_extraction": counts["sft_classification"],
                          "poc_claim_extraction": counts["sft_poc_association"],
                          "reviewed_preference": 0,
                          "repair_advice": 0, "attack_path_analysis": 0,
                          "semantic_retrieval_benchmark": 0},
        "readiness": {"sft": "source-grounded; labels require independent audit",
                      "preference_optimization": "awaiting human reviewed pairs",
                      "retrieval": "CVE lookup only; negatives require review",
                      "code_training_rights": "license review required before training or redistribution",
                      "requirements_fully_met": False},
        "supported_paradigms": ["knowledge_injection", "instruction_tuning", "supervised_fine_tuning",
                                "retrieval_augmented_generation",
                                "retrieval_training_and_evaluation"],
        "validation": validation,
        "artifacts": artifacts,
    }
    (target / "manifest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report
