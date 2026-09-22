"""Independently check exported training JSONL without modifying the source DB."""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re


def validate(target: Path) -> dict:
    manifest = json.loads((target / "manifest.json").read_text(encoding="utf-8"))
    errors = []
    doc_splits, references = {}, []
    content_splits = defaultdict(set)
    vuln_splits, family_splits = defaultdict(set), defaultdict(set)
    formal_ids, manifest_ids, candidate_ids = set(), set(), set()
    rows_by_file = {}
    for name, artifact in manifest["artifacts"].items():
        path = target / name
        file_hash, rows, ids = hashlib.sha256(), 0, set()
        with path.open("rb") as handle:
            for raw in handle:
                file_hash.update(raw)
                row = json.loads(raw)
                rows += 1
                identity = row.get("sample_id") or row.get("doc_id")
                if identity in ids:
                    errors.append(f"{name}: duplicate id {identity}")
                ids.add(identity)
                split = row.get("split")
                if split not in {"train", "validation", "test"}:
                    errors.append(f"{name}: invalid split {split}")
                for cve in row.get("vuln_ids", [row.get("vuln_id")]):
                    if cve:
                        vuln_splits[cve].add(split)
                family_splits[row["family_id"]].add(split)
                if name == "rag-corpus.jsonl":
                    doc_splits[identity] = split
                    normalized = re.sub(r"\s+", " ", row["text"]).strip()
                    text_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
                    content_splits[text_hash].add(split)
                    if text_hash != row["content_sha256"]:
                        errors.append(f"{name}: wrong content hash {identity}")
                elif name == "retrieval.jsonl":
                    references.extend((identity, split, doc) for doc in
                                      row["positive_doc_ids"] + row["hard_negative_doc_ids"])
                    formal_ids.add(identity)
                elif name == "sft.jsonl":
                    formal_ids.add(identity)
                    if row["task"] == "grounded_metadata_extraction":
                        evidence = json.loads(row["messages"][1]["content"].split("\n", 1)[1])
                        answer = json.loads(row["messages"][-1]["content"])
                        if answer != evidence["source_assertions"]:
                            errors.append(f"{name}: unsupported target {identity}")
                    elif row["task"] == "poc_claim_extraction":
                        answer = json.loads(row["messages"][-1]["content"])
                        if answer["replay_verified"] and answer["verification_status"] != "sandbox_verified":
                            errors.append(f"{name}: unsupported replay claim {identity}")
                elif name == "preference-candidates.jsonl":
                    candidate_ids.add(identity)
                    if row.get("training_eligible") is not False or not row.get("requires_human_review"):
                        errors.append(f"{name}: candidate not quarantined {identity}")
                elif name == "dataset-manifest.jsonl":
                    manifest_ids.add(identity)
        if (rows != artifact["rows"] or path.stat().st_size != artifact["bytes"]
                or file_hash.hexdigest() != artifact["sha256"]):
            errors.append(f"{name}: snapshot mismatch")
        rows_by_file[name] = rows
    missing_refs = sum(doc not in doc_splits for _, _, doc in references)
    cross_refs = sum(doc in doc_splits and doc_splits[doc] != split for _, split, doc in references)
    leakage = {"vulnerability": sum(len(splits) > 1 for splits in vuln_splits.values()),
               "family": sum(len(splits) > 1 for splits in family_splits.values()),
               "normalized_rag_content": sum(len(splits) > 1 for splits in content_splits.values())}
    if missing_refs or cross_refs or any(leakage.values()):
        errors.append("Missing references or cross-split leakage detected")
    if manifest_ids != formal_ids or candidate_ids & manifest_ids:
        errors.append("Formal sample manifest is inconsistent or contains review candidates")
    return {"status": "passed" if not errors else "failed", "dataset_id": manifest["dataset_id"],
            "rows": rows_by_file, "leakage": leakage, "missing_doc_references": missing_refs,
            "cross_split_doc_references": cross_refs, "errors": errors,
            "note": "Structural checks do not establish source truth, semantic relevance or licensing rights."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    report = validate(args.directory)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report["status"] == "passed" else 1)
