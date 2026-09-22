"""Evidence-preserving merge, missing-field discovery and static modality extraction."""
from __future__ import annotations

import ast
from collections import defaultdict
import html
from pathlib import Path
import re
from typing import Any
import unicodedata
from urllib.parse import unquote

from .models import FIELDS, SCHEMA, SourceRecord, canonical_json, digest, unique

PRIORITY = {"cve": 0, "nvd": 1, "avd": 2, "cnnvd": 3}
CODE_BLOCK = re.compile(r"```([^\n`]*)\n(.*?)```", re.S)
HTML_CODE_BLOCK = re.compile(r"<pre(?:\s[^>]*)?>\s*<code(?:\s[^>]*)?>(.*?)</code>\s*</pre>", re.I | re.S)
MARKDOWN_IMAGE = re.compile(r"!\[([^\]]*)\]\(([^)\s]+)(?:\s+['\"][^'\"]*['\"])?\)")


def _entity_token(value: Any) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"[^a-z0-9\u3400-\u9fff]+", "", text)


def _purl_coordinate(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text.casefold().startswith("pkg:"):
        return None
    coordinate = unquote(text.split("#", 1)[0].split("?", 1)[0])
    slash = coordinate.rfind("/")
    at = coordinate.rfind("@")
    if at > slash:
        coordinate = coordinate[:at]
    return coordinate.casefold() if "/" in coordinate else None


def _cpe_coordinate(value: Any) -> str | None:
    text = str(value or "").strip()
    match = re.match(r"^cpe:2\.3:([aho]):([^:]+):([^:]+):", text, re.I)
    if not match:
        return None
    return "cpe:2.3:" + ":".join(_entity_token(item) for item in match.groups())


def _component_candidate(component: Any, source: SourceRecord, position: int) -> dict[str, Any]:
    if isinstance(component, str):
        component = {"name": component}
    if not isinstance(component, dict):
        raise ValueError("Component assertions must be strings or objects")
    vendor = str(component.get("vendor") or "").strip()
    name = str(component.get("name") or component.get("product") or component.get("packageName") or "").strip()
    purls = unique([item for item in [_purl_coordinate(component.get("packageURL"))] if item])
    listed_cpes = component.get("cpes") or []
    if isinstance(listed_cpes, str):
        listed_cpes = [listed_cpes]
    if not isinstance(listed_cpes, list):
        raise ValueError("Component cpes must be a string or array")
    raw_cpes = [component.get("cpe"), *listed_cpes]
    cpes = unique([item for item in (_cpe_coordinate(value) for value in raw_cpes) if item])
    fallback = f"name:{_entity_token(vendor)}:{_entity_token(name)}" if vendor and name else None
    return {
        "component": component, "source": source.source, "source_id": source.source_id,
        "position": position, "vendor": vendor, "name": name,
        "purls": set(purls), "cpes": set(cpes), "fallback": fallback,
    }


def _strong_compatible(left: dict[str, Any], right: dict[str, Any]) -> bool:
    for kind in ("purls", "cpes"):
        if left[kind] and right[kind] and not left[kind].intersection(right[kind]):
            return False
    return True


def disambiguate_components(records: list[SourceRecord]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Conservatively resolve product assertions using PURL, CPE, then vendor/name.

    Disjoint identifiers are never collapsed merely because their display name is
    similar.  Ambiguities remain separate and are returned as review findings.
    """
    candidates = []
    for source in records:
        for position, component in enumerate(source.fields.get("components") or []):
            candidates.append(_component_candidate(component, source, position))
    clusters: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for candidate in candidates:
        selected = None
        for cluster in clusters:
            strong_match = bool(candidate["purls"] & cluster["purls"] or candidate["cpes"] & cluster["cpes"])
            fallback_match = bool(candidate["fallback"] and candidate["fallback"] == cluster["fallback"])
            if strong_match:
                if not _strong_compatible(candidate, cluster):
                    findings.append({
                        "kind": "conflicting_component_identifiers", "vendor": candidate["vendor"],
                        "name": candidate["name"], "left_sources": sorted(cluster["sources"]),
                        "right_source": f"{candidate['source']}:{candidate['source_id']}",
                        "matched_on_another_strong_identifier": True,
                    })
                selected = cluster
                break
            if fallback_match and _strong_compatible(candidate, cluster):
                selected = cluster
                break
            if fallback_match and not _strong_compatible(candidate, cluster):
                findings.append({
                    "kind": "conflicting_component_identifiers", "vendor": candidate["vendor"],
                    "name": candidate["name"], "left_sources": sorted(cluster["sources"]),
                    "right_source": f"{candidate['source']}:{candidate['source_id']}",
                })
        if selected is None:
            selected = {
                "items": [], "purls": set(), "cpes": set(), "fallback": candidate["fallback"],
                "sources": set(), "vendors": set(), "names": set(),
            }
            clusters.append(selected)
        selected["items"].append(candidate["component"])
        selected["purls"].update(candidate["purls"])
        selected["cpes"].update(candidate["cpes"])
        selected["sources"].add(f"{candidate['source']}:{candidate['source_id']}")
        if candidate["vendor"]:
            selected["vendors"].add(candidate["vendor"])
        if candidate["name"]:
            selected["names"].add(candidate["name"])

    resolved = []
    for cluster in clusters:
        items = cluster["items"]
        purls, cpes = sorted(cluster["purls"]), sorted(cluster["cpes"])
        fallback = cluster["fallback"]
        if purls:
            basis, identity, confidence = "purl", purls[0], "high"
        elif cpes:
            basis, identity, confidence = "cpe", cpes[0], "high"
        elif fallback:
            basis, identity, confidence = "vendor_product", fallback, "medium"
        else:
            basis = "unresolved"
            identity = "unresolved:" + digest([sorted(cluster["sources"]), items])
            confidence = "low"
            findings.append({"kind": "unresolved_component_identity", "sources": sorted(cluster["sources"])})
        versions = unique([version for item in items for version in (item.get("versions") or [])])
        statuses = unique([str(item.get("default_status", "unknown")) for item in items
                           if item.get("default_status", "unknown") != "unknown"])
        default_status = statuses[0] if len(statuses) == 1 else "unknown"
        if len(statuses) > 1:
            findings.append({"kind": "conflicting_component_status", "entity": identity,
                             "values": statuses, "sources": sorted(cluster["sources"])})
        vendor = sorted(cluster["vendors"], key=lambda value: (_entity_token(value), value))[0] if cluster["vendors"] else ""
        name = sorted(cluster["names"], key=lambda value: (_entity_token(value), value))[0] if cluster["names"] else ""
        output: dict[str, Any] = {
            "vendor": vendor, "name": name, "versions": versions, "default_status": default_status,
            "entity_id": "component:" + digest(identity)[:24],
            "identity": {
                "basis": basis, "confidence": confidence,
                "purls": purls, "cpes": cpes,
                "aliases": sorted(unique([
                    {"vendor": str(item.get("vendor") or ""),
                     "name": str(item.get("name") or item.get("product") or item.get("packageName") or "")}
                    for item in items
                ]), key=canonical_json),
                "sources": sorted(cluster["sources"]),
            },
        }
        if purls:
            output["packageURL"] = purls[0]
        if cpes:
            output["cpes"] = cpes
        for key in ("packageName", "collectionURL", "modules"):
            values = unique([item[key] for item in items if item.get(key) not in (None, "", [])])
            if len(values) == 1:
                output[key] = values[0]
            elif len(values) > 1:
                output[key] = values
        resolved.append(output)
    return sorted(resolved, key=lambda item: item["entity_id"]), findings


def normalized_text(value: str) -> str:
    """Stable text form used by every modality without rewriting the evidence."""
    return re.sub(r"\s+", " ", html.unescape(value)).strip()


def code_behavior_features(code: str, language: str = "") -> dict[str, Any]:
    """Static, language-tolerant behavior hints; code is never imported or run."""
    text = code.lower()
    patterns = {
        "network": r"\b(socket|connect|requests(?:\.|\b)|urllib|curl|wget|http[s]?://)",
        "process": r"\b(subprocess|popen|execve|system\s*\(|createprocess|runtime\.getruntime)",
        "filesystem": r"\b(open\s*\(|write\s*\(|unlink|remove\s*\(|pathlib|fopen|ofstream)",
        "command_execution": r"\b(eval\s*\(|exec\s*\(|shell\s*=\s*true|cmd\.exe|/bin/sh)",
        "encoding": r"\b(base64|hexlify|fromhex|decode\s*\()",
        "database": r"\b(select|insert|update|delete)\b|\b(execute|query)\s*\(",
        "memory": r"\b(memcpy|malloc|free\s*\(|virtualalloc|mmap\s*\()",
    }
    features = {name: bool(re.search(pattern, text)) for name, pattern in patterns.items()}
    result: dict[str, Any] = {
        "language": language.strip().lower() or "unknown",
        "line_count": len(code.splitlines()),
        "behaviors": sorted(name for name, present in features.items() if present),
    }
    if result["language"] in {"python", "py"}:
        result["syntax"] = static_python_features(code)
    return result


def extract_modalities(value: str, field: str = "description") -> list[dict[str, Any]]:
    """Locate text, fenced/HTML code and image references in one source field."""
    if not isinstance(value, str) or not value.strip():
        return []
    segments: list[dict[str, Any]] = []
    modality = "image_transcript" if field == "image_text" else "patch" if field == "patch" else "code" if field == "poc" else "text"
    segments.append({
        "modality": modality, "text": value,
        "locator": {"field": field, "start": 0, "end": len(value)},
        "extraction": "source_field",
        "representation": {"schema": "aligned/v1", "text": normalized_text(value), "content_hash": digest(value)},
    })
    occupied: set[tuple[int, int]] = set()
    for match in CODE_BLOCK.finditer(value):
        occupied.add((match.start(2), match.end(2)))
        code = match.group(2)
        language = match.group(1).strip()
        segments.append({
            "modality": "code", "language": language, "text": code,
            "locator": {"field": field, "start": match.start(2), "end": match.end(2)},
            "extraction": "markdown_fence/v1",
            "representation": {"schema": "aligned/v1", "text": normalized_text(code), "content_hash": digest(code), "code_behavior": code_behavior_features(code, language)},
        })
    for match in HTML_CODE_BLOCK.finditer(value):
        start, end = match.start(1), match.end(1)
        if (start, end) in occupied:
            continue
        code = html.unescape(re.sub(r"<[^>]+>", "", match.group(1)))
        segments.append({
            "modality": "code", "language": "", "text": code,
            "locator": {"field": field, "start": start, "end": end},
            "extraction": "html_pre_code/v1",
            "representation": {"schema": "aligned/v1", "text": normalized_text(code), "content_hash": digest(code), "code_behavior": code_behavior_features(code)},
        })
    for match in MARKDOWN_IMAGE.finditer(value):
        segments.append({
            "modality": "image_reference", "text": match.group(1).strip(), "uri": match.group(2),
            "locator": {"field": field, "start": match.start(), "end": match.end()},
            "extraction": "markdown_image/v1",
            "representation": {"schema": "aligned/v1", "text": normalized_text(match.group(1)), "content_hash": digest(match.group(2))},
        })
    return segments


def modality_evidence(record: SourceRecord) -> list[dict[str, Any]]:
    entries = []
    for field in ("description", "poc", "patch", "image_text"):
        value = record.fields.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        for segment in extract_modalities(value, field):
            segment.update({
                "evidence_id": digest([record.source, record.source_id, field, segment["locator"], segment.get("text"), segment.get("uri")]),
                "source": record.source, "source_id": record.source_id, "url": record.url, "field": field,
                "confidence": "unverified" if field == "image_text" or segment["modality"] == "image_reference" else "source_asserted" if segment["extraction"] == "source_field" else "extracted",
            })
            entries.append(segment)
    for artifact in record.fields.get("image_embeddings") or []:
        if not isinstance(artifact, dict):
            continue
        entries.append({
            "evidence_id": digest([record.source, record.source_id, "image_embedding",
                                   artifact.get("content_hash"), artifact.get("model_id")]),
            "source": record.source, "source_id": record.source_id, "url": record.url,
            "field": "image_embeddings", "modality": "image_embedding",
            "locator": {"content_hash": artifact.get("content_hash")},
            "extraction": "local_native_vision/v1", "confidence": "machine_extracted",
            "representation": {
                "schema": "aligned/v1", "content_hash": artifact.get("content_hash"),
                "model_id": artifact.get("model_id"), "dimension": artifact.get("dimension"),
                "embedding_hash": artifact.get("embedding_hash"), "native_vision": True,
            },
        })
    return entries


def alignment_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize aligned evidence and flag modalities that need human review."""
    from collections import Counter
    modalities: Counter[str] = Counter()
    extraction: Counter[str] = Counter()
    behavior: Counter[str] = Counter()
    findings = []
    active = [record for record in records if record.get("status") == "active"]
    for record in active:
        evidence = record.get("evidence", [])
        if not evidence:
            findings.append({"vuln_id": record["vuln_id"], "kind": "no_modality_evidence"})
        for item in evidence:
            modalities[item.get("modality", "unknown")] += 1
            extraction[item.get("extraction", "unknown")] += 1
            representation = item.get("representation") or {}
            for name in representation.get("code_behavior", {}).get("behaviors", []):
                behavior[name] += 1
            if item.get("confidence") == "unverified":
                findings.append({"vuln_id": record["vuln_id"], "kind": "unverified_evidence", "evidence_id": item.get("evidence_id"), "modality": item.get("modality")})
    return {
        "schema": "vulntools/alignment/v1", "records": len(records), "active": len(active),
        "evidence": sum(modalities.values()), "modalities": dict(modalities),
        "extraction_methods": dict(extraction), "code_behaviors": dict(behavior),
        "findings": findings, "aligned": all("representation" in item for record in active for item in record.get("evidence", [])),
    }


def static_python_features(code: str) -> dict[str, Any]:
    """Parse, never execute; a syntactic feature list is not an exploit verdict."""
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"language": "python", "parse_error": str(exc), "calls": [], "imports": []}
    calls, imports = [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(ast.unparse(node.func))
        elif isinstance(node, ast.Import):
            imports.extend(x.name for x in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    return {"language": "python", "parse_error": None, "calls": sorted(set(calls)), "imports": sorted(set(imports))}


def process(records: list[SourceRecord]) -> list[dict[str, Any]]:
    groups: dict[str, list[SourceRecord]] = defaultdict(list)
    # Exact CVE identities only. Shared references/similarity never imply identity.
    for record in records:
        groups[record.vuln_id].append(record)
    result = []
    for vuln_id, members in sorted(groups.items()):
        members.sort(key=lambda x: (PRIORITY[x.source], x.source_id))
        active = [x for x in members if x.status == "active"]
        # Official CVE rejection takes precedence; other rejection disagreement stays visible.
        rejected = any(x.source == "cve" and x.status == "rejected" for x in members) or not active
        fields, states, provenance, conflicts = {}, {}, {}, {}
        component_review: list[dict[str, Any]] = []
        for name in unique([*FIELDS, *(key for member in active for key in member.fields)]):
            candidates = [{"value": member.fields[name], "source": member.source, "source_id": member.source_id, "url": member.url,
                           "raw_hash": digest(member.raw)} for member in active if member.fields.get(name) not in (None, "", [])]
            provenance[name] = candidates
            if not candidates:
                fields[name], states[name] = None, "missing"
                continue
            if name == "components":
                fields[name], component_review = disambiguate_components(active)
                states[name] = "present" if fields[name] else "missing"
                continue
            values = unique([x["value"] for x in candidates])
            fields[name] = values[0]
            states[name] = "present" if len(values) == 1 else "conflicted"
            if len(values) > 1:
                conflicts[name] = candidates
        evidence = [e for member in active for e in modality_evidence(member)]
        record = {"schema_version": SCHEMA, "vuln_id": vuln_id, "aliases": unique([a for member in members for a in member.aliases]),
                  "status": "rejected" if rejected else "active", "fields": fields, "field_states": states,
                  "provenance": provenance, "conflicts": conflicts, "evidence": evidence,
                  "entity_review": component_review,
                  "references": unique([u for member in members for u in [member.url, *member.references]]),
                  "sources": [{"source": x.source, "source_id": x.source_id, "url": x.url, "status": x.status, "raw_hash": digest(x.raw)} for x in members]}
        record["revision"] = digest(record)
        result.append(record)
    return result


def enrichment_plan(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Offline plans. Executing an external search is deliberately a separate provider."""
    plans = []
    for record in records:
        if record["status"] != "active":
            continue
        missing = [name for name in FIELDS if record["field_states"].get(name) == "missing"]
        if missing:
            plans.append({"vuln_id": record["vuln_id"], "missing_fields": missing, "queries": [f"{record['vuln_id']} {name}" for name in missing],
                          "status": "awaiting_search_provider", "max_requests": 5,
                          "policy": "Import source evidence then reprocess; never fill from a search snippet alone."})
    return plans


def duplicate_candidates(records: list[dict[str, Any]], threshold: float = 0.65) -> list[dict[str, Any]]:
    """Small-corpus lexical candidate discovery; never mutate/merge an identity."""
    from .embedding import tokens
    if not 0 < threshold <= 1:
        raise ValueError("Duplicate threshold must be in (0, 1]")
    active = [r for r in records if r["status"] == "active"]
    terms = [set(tokens(str(r["fields"].get("description") or ""))) for r in active]
    candidates = []
    for i, left in enumerate(active):
        for j in range(i + 1, len(active)):
            union = terms[i] | terms[j]
            score = len(terms[i] & terms[j]) / len(union) if union else 0
            if score >= threshold:
                candidates.append({"left": left["vuln_id"], "right": active[j]["vuln_id"], "score": score,
                                   "method": "description-token-jaccard/v1", "decision": "needs_review"})
    return sorted(candidates, key=lambda x: (-x["score"], x["left"], x["right"]))


def ocr_image(path: str | Path, language: str = "eng") -> dict[str, Any]:
    """Optional offline OCR. Requires installed Tesseract binary and language packs."""
    try:
        from PIL import Image
        import pytesseract
    except ImportError as exc:
        raise RuntimeError("Install the ocr extra and local Tesseract before using OCR") from exc
    path = Path(path)
    with Image.open(path) as picture:
        data = pytesseract.image_to_data(picture, lang=language, output_type=pytesseract.Output.DICT)
    words = [{"text": text, "confidence": float(data["conf"][i]), "box": [data["left"][i], data["top"][i], data["width"][i], data["height"][i]]}
             for i, text in enumerate(data["text"]) if text.strip()]
    import hashlib
    return {"schema_version": SCHEMA, "modality": "image", "path": str(path.resolve()), "content_hash": hashlib.sha256(path.read_bytes()).hexdigest(),
            "extractor": "tesseract", "language": language, "text": " ".join(x["text"] for x in words), "words": words}
