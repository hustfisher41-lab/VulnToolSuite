"""Version-aware multi-view vector, lexical, and hybrid vulnerability retrieval."""
from __future__ import annotations

from collections import Counter
import heapq
import json
import math
import re
import time
from typing import Any, Iterable

from .embedding import Encoder, encode_query_text, tokens, validate_vector
from .models import digest
from .storage import Store


SCALABLE_SCAN_THRESHOLD = 10_000


def numeric_version(value: str) -> tuple[int, ...] | None:
    # Intentionally narrow: no guessing pre-release ordering or vendor versions.
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    parts = [int(x) for x in value.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _semver(value: str) -> tuple[tuple[int, int, int], tuple[tuple[int, Any], ...] | None] | None:
    match = re.fullmatch(r"[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", value.strip())
    if not match:
        return None
    core = tuple(int(match.group(index) or 0) for index in range(1, 4))
    prerelease = match.group(4)
    if prerelease is None:
        return core, None
    identifiers: list[tuple[int, Any]] = []
    for item in prerelease.split("."):
        identifiers.append((0, int(item)) if item.isdigit() else (1, item.casefold()))
    return core, tuple(identifiers)


def _compare_semver(left: str, right: str) -> int | None:
    first, second = _semver(left), _semver(right)
    if first is None or second is None:
        return None
    if first[0] != second[0]:
        return (first[0] > second[0]) - (first[0] < second[0])
    if first[1] is None or second[1] is None:
        return (first[1] is None) - (second[1] is None)
    for a, b in zip(first[1], second[1]):
        if a == b:
            continue
        if a[0] != b[0]:  # Numeric identifiers have lower precedence.
            return -1 if a[0] == 0 else 1
        return (a[1] > b[1]) - (a[1] < b[1])
    return (len(first[1]) > len(second[1])) - (len(first[1]) < len(second[1]))


def _pep440(value: str) -> tuple[Any, ...] | None:
    match = re.fullmatch(
        r"[vV]?(\d+(?:\.\d+)*)(?:(a|b|rc)(\d+))?(?:\.post(\d+))?(?:\.dev(\d+))?",
        value.strip(), re.I,
    )
    if not match:
        return None
    release = list(numeric_version(match.group(1)) or ())
    release += [0] * (4 - len(release))
    pre_name = (match.group(2) or "").casefold()
    pre_rank = {"a": 0, "b": 1, "rc": 2}.get(pre_name, 3)
    pre_number = int(match.group(3) or 0)
    # dev < pre < final < post for the supported, unambiguous subset.
    if match.group(5) is not None:
        phase = -1
        phase_number = int(match.group(5))
    elif pre_name:
        phase = pre_rank
        phase_number = pre_number
    elif match.group(4) is not None:
        phase = 4
        phase_number = int(match.group(4))
    else:
        phase = 3
        phase_number = 0
    return (*release[:4], phase, phase_number)


def _maven(value: str) -> tuple[tuple[int, int, str], ...] | None:
    if not re.fullmatch(r"[0-9A-Za-z_.+-]+", value.strip()):
        return None
    qualifier = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "milestone": -3, "m": -3,
                 "rc": -2, "cr": -2, "snapshot": -1, "": 0, "final": 0, "ga": 0, "release": 0, "sp": 1}
    pieces = re.findall(r"\d+|[A-Za-z]+", value.casefold())
    result = [(1, int(piece), "") if piece.isdigit()
              else (0, qualifier.get(piece, 0), "" if piece in qualifier else piece) for piece in pieces]
    while result and result[-1] in {(1, 0, ""), (0, 0, "")}:
        result.pop()
    return tuple(result)


def compare_versions(left: str, right: str, version_type: str) -> int | None:
    """Compare only explicitly supported ecosystems; return None rather than guess."""
    kind = version_type.casefold().replace("_", "-")
    if kind in {"semver", "npm", "cargo", "golang", "go"}:
        return _compare_semver(left, right)
    if kind in {"numeric", "number"}:
        a, b = numeric_version(left), numeric_version(right)
    elif kind in {"python", "pep440", "pypi"}:
        a, b = _pep440(left), _pep440(right)
    elif kind in {"maven", "maven-version"}:
        a, b = _maven(left), _maven(right)
    elif kind in {"date", "calendar"}:
        if not re.fullmatch(r"\d{4}(?:[-.]\d{1,2}){1,2}", left) or not re.fullmatch(r"\d{4}(?:[-.]\d{1,2}){1,2}", right):
            return None
        a = tuple(int(item) for item in re.split(r"[-.]", left))
        b = tuple(int(item) for item in re.split(r"[-.]", right))
    else:
        return None
    if a is None or b is None:
        return None
    return (a > b) - (a < b)


def _inferred_version_type(component: dict[str, Any], rule: dict[str, Any]) -> str:
    explicit = str(rule.get("versionType") or "").casefold()
    if explicit and explicit not in {"unknown", "custom"}:
        return explicit
    purl = str(component.get("packageURL") or "")
    match = re.match(r"pkg:([^/]+)/", purl, re.I)
    ecosystem = match.group(1).casefold() if match else ""
    return {"pypi": "pep440", "npm": "semver", "cargo": "semver", "golang": "semver",
            "maven": "maven"}.get(ecosystem, explicit or "unknown")


def version_match(component: dict[str, Any], version: str) -> str:
    uncertain = False
    for rule in component.get("versions", []):
        if isinstance(rule, str):
            rule = {"version": rule, "status": "affected"}
        lower = str(rule.get("version", ""))
        bounds = {k: rule[k] for k in ("lessThan", "lessThanOrEqual", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if k in rule}
        if not bounds:
            version_type = _inferred_version_type(component, rule)
            comparison = compare_versions(version, lower, version_type)
            if lower == version or comparison == 0:
                return "affected" if rule.get("status") == "affected" else "unaffected" if rule.get("status") == "unaffected" else "unknown"
        if bounds:
            version_type = _inferred_version_type(component, rule)
            target_lower = compare_versions(version, lower, version_type) if lower not in {"", "*", "n/a"} else None
            comparisons = {key: compare_versions(version, str(value), version_type) for key, value in bounds.items()}
            if any(value is None for value in comparisons.values()):
                uncertain = True
                continue
            accepted = True
            if "lessThan" in bounds or "lessThanOrEqual" in bounds:
                if target_lower is None:
                    uncertain = True
                    continue
                accepted = target_lower >= 0
            for key, comparison in comparisons.items():
                accepted = accepted and ({"lessThan": comparison < 0, "lessThanOrEqual": comparison <= 0,
                                          "versionStartIncluding": comparison >= 0, "versionStartExcluding": comparison > 0,
                                          "versionEndIncluding": comparison <= 0, "versionEndExcluding": comparison < 0}[key])
            if accepted:
                status = rule.get("status")
                applicable_changes = []
                for change in rule.get("changes") or []:
                    at = str(change.get("at") or "")
                    comparison = compare_versions(version, at, version_type) if at else None
                    if comparison is None:
                        uncertain = True
                    elif comparison >= 0 and change.get("status") in {"affected", "unaffected"}:
                        applicable_changes.append((at, change["status"]))
                if applicable_changes:
                    # Pairwise comparison avoids relying on ecosystem-specific tuple shapes.
                    latest = applicable_changes[0]
                    for candidate in applicable_changes[1:]:
                        if compare_versions(candidate[0], latest[0], version_type) == 1:
                            latest = candidate
                    status = latest[1]
                return status if status in {"affected", "unaffected"} else "unknown"
        elif lower in {"", "*", "n/a"}:
            uncertain = True
    if uncertain:
        return "unknown"
    return component.get("default_status", "unknown") if component.get("default_status") in {"affected", "unaffected"} else "unknown"


def _split_cpe(value: str) -> list[str] | None:
    if not value.startswith("cpe:2.3:"):
        return None
    parts, current, escaped = [], [], False
    for character in value[8:]:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))
    return parts if len(parts) == 11 else None


def _cpe_match(match: dict[str, Any], targets: list[str]) -> bool | None:
    criteria = _split_cpe(str(match.get("criteria") or ""))
    parsed_targets = [_split_cpe(value) for value in targets]
    if criteria is None or any(value is None for value in parsed_targets):
        return None
    for target in parsed_targets:
        assert target is not None
        if any(expected not in {"*", "-"} and expected.casefold() != actual.casefold()
               for expected, actual in zip(criteria[:4], target[:4])):
            continue
        target_version = target[3]
        bounds = {key: str(match[key]) for key in (
            "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding") if key in match}
        if bounds:
            kind = "semver" if _semver(target_version) and all(_semver(value) for value in bounds.values()) else "numeric"
            compared = {key: compare_versions(target_version, value, kind) for key, value in bounds.items()}
            if any(value is None for value in compared.values()):
                return None
            if not all({"versionStartIncluding": value >= 0, "versionStartExcluding": value > 0,
                        "versionEndIncluding": value <= 0, "versionEndExcluding": value < 0}[key]
                       for key, value in compared.items()):
                continue
        elif criteria[3] not in {"*", "-"} and criteria[3].casefold() != target_version.casefold():
            continue
        return True
    return False


def _cpe_node(node: dict[str, Any], targets: list[str]) -> bool | None:
    values: list[bool | None] = [_cpe_match(item, targets) for item in node.get("cpeMatch", [])]
    values.extend(_cpe_node(child, targets) for child in node.get("children", []))
    if not values:
        return None
    operator = str(node.get("operator") or "OR").upper()
    if operator == "AND":
        result: bool | None = False if False in values else None if None in values else True
    elif operator == "OR":
        result = True if True in values else None if None in values else False
    else:
        return None
    if node.get("negate") is True and result is not None:
        result = not result
    return result


def _vulnerable_cpe_present(node: dict[str, Any], targets: list[str]) -> bool | None:
    vulnerable_matches = [item for item in node.get("cpeMatch", []) if item.get("vulnerable") is True]
    stack = list(node.get("children", []))
    while stack:
        child = stack.pop()
        vulnerable_matches.extend(item for item in child.get("cpeMatch", []) if item.get("vulnerable") is True)
        stack.extend(child.get("children", []))
    if not vulnerable_matches:
        return None
    values = [_cpe_match(item, targets) for item in vulnerable_matches]
    return True if True in values else None if None in values else False


def cpe_applicability(configurations: Any, targets: list[str]) -> str:
    """Evaluate the NVD configuration tree against a complete target CPE context."""
    if not targets or not isinstance(configurations, list) or not configurations:
        return "unknown"
    outcomes: list[bool | None] = []
    for configuration in configurations:
        if not isinstance(configuration, dict):
            outcomes.append(None)
            continue
        nodes = configuration.get("nodes")
        if isinstance(nodes, list):
            synthetic = {"operator": configuration.get("operator", "OR"), "negate": configuration.get("negate", False),
                         "children": nodes}
            condition = _cpe_node(synthetic, targets)
            vulnerable = _vulnerable_cpe_present(synthetic, targets)
        else:
            condition = _cpe_node(configuration, targets)
            vulnerable = _vulnerable_cpe_present(configuration, targets)
        outcomes.append(True if condition is True and vulnerable is True
                        else None if condition is None or (condition is True and vulnerable is None)
                        else False)
    return "affected" if True in outcomes else "unknown" if None in outcomes else "unaffected"


def matches(record: dict[str, Any], severity: str | None, component: str | None, version: str | None,
            cpes: list[str] | None = None) -> tuple[bool, str]:
    fields = record["fields"]
    if severity and str(fields.get("severity", "")).lower() != severity.lower():
        return False, "not_checked"
    if component:
        candidates = [x for x in fields.get("components") or [] if isinstance(x, dict) and x.get("name", "").casefold() == component.casefold()]
        if not candidates:
            return False, "unknown"
        if version:
            if record["field_states"].get("components") == "conflicted":
                return False, "unknown"
            statuses = [version_match(x, version) for x in candidates]
            return "affected" in statuses, "affected" if "affected" in statuses else "unknown" if "unknown" in statuses else "unaffected"
    if cpes:
        applicability = cpe_applicability(fields.get("applicability"), cpes)
        if applicability != "affected":
            return False, applicability
        return True, "affected"
    return True, "not_checked"


def cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Vectors must have the same dimension")
    if not left:
        raise ValueError("Vectors cannot be empty")
    if any(not math.isfinite(x) for x in [*left, *right]):
        raise ValueError("Vectors must contain only finite values")
    left_norm = math.sqrt(sum(x * x for x in left))
    right_norm = math.sqrt(sum(x * x for x in right))
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm) if left_norm and right_norm else 0.0


def index_status(store: Store, encoder: Encoder) -> dict[str, Any]:
    model_id = digest(encoder.manifest)
    active = store.db.execute("SELECT count(*) FROM canonical WHERE json_extract(payload,'$.status')='active'").fetchone()[0]
    indexed = store.db.execute("""SELECT count(*) FROM vectors v JOIN canonical c
        ON c.vuln_id=v.vuln_id AND c.revision=v.revision WHERE v.model_id=?
        AND json_extract(c.payload,'$.status')='active'""", (model_id,)).fetchone()[0]
    views = {row[0]: row[1] for row in store.db.execute("""SELECT vv.view_name,count(*) FROM vector_views vv
        JOIN canonical c ON c.vuln_id=vv.vuln_id AND c.revision=vv.revision
        WHERE vv.model_id=? AND json_extract(c.payload,'$.status')='active' GROUP BY vv.view_name ORDER BY vv.view_name""", (model_id,))}
    missing_count = max(0, active - indexed)
    missing = [row[0] for row in store.db.execute("""SELECT c.vuln_id FROM canonical c
        LEFT JOIN vectors v ON v.vuln_id=c.vuln_id AND v.revision=c.revision AND v.model_id=?
        WHERE json_extract(c.payload,'$.status')='active' AND v.vuln_id IS NULL
        ORDER BY c.vuln_id LIMIT 100""", (model_id,))]
    multiview_ready = views.get("aggregate", 0) == indexed
    scalable = indexed > SCALABLE_SCAN_THRESHOLD
    return {"model_id": model_id, "model_registered": bool(store.db.execute(
                "SELECT 1 FROM vector_models WHERE model_id=?", (model_id,)).fetchone()),
            "active_records": active, "indexed_records": indexed,
            "missing_record_count": missing_count, "missing_records": missing,
            "missing_records_truncated": missing_count > len(missing),
            "views": views, "view_schema": "multiview/v1" if multiview_ready else None,
            "backend": {"kind": "sqlite_two_stage" if scalable else "sqlite_exact",
                        "approximate": scalable, "distance": "cosine",
                        "candidate_complexity": "linear_stream_then_bounded_rerank" if scalable else "linear"},
            "ready": active > 0 and missing_count == 0 and multiview_ready}


def _bm25(query_terms: set[str], documents: list[str]) -> tuple[dict[int, float], list[Counter]]:
    counts = [Counter(tokens(document)) for document in documents]
    lengths = [sum(item.values()) for item in counts]
    average = sum(lengths) / len(lengths) or 1
    frequency = Counter(term for item in counts for term in item)
    scores: dict[int, float] = {}
    for i, item in enumerate(counts):
        scores[i] = sum(
            math.log(1 + (len(documents) - frequency[term] + .5) / (frequency[term] + .5))
            * (item[term] * 2.2 / (item[term] + 1.2 * (.25 + .75 * lengths[i] / average)))
            for term in query_terms if item[term]
        )
    return scores, counts


def _rank(scores: dict[int, float]) -> list[int]:
    return sorted((i for i, value in scores.items() if value > 0), key=lambda i: (-scores[i], i))


def search(store: Store, encoder: Encoder, query: str = "", *, poc: str = "", component: str | None = None,
           version: str | None = None, severity: str | None = None, weakness: str | None = None,
           source: str | None = None, top_k: int = 10, offset: int = 0, mode: str = "hybrid",
           min_similarity: float | None = None, cpes: list[str] | None = None) -> list[dict[str, Any]]:
    if not 1 <= top_k <= 100:
        raise ValueError("top_k must be between 1 and 100")
    if not 0 <= offset <= 10000:
        raise ValueError("offset must be between 0 and 10000")
    if mode not in {"hybrid", "dense", "sparse"}:
        raise ValueError("mode must be hybrid, dense or sparse")
    if min_similarity is not None and not -1 <= min_similarity <= 1:
        raise ValueError("min_similarity must be between -1 and 1")
    if version and not component:
        raise ValueError("A version filter requires a component")
    if cpes is not None and (not isinstance(cpes, list) or not cpes or any(_split_cpe(value) is None for value in cpes)):
        raise ValueError("cpes must be a nonempty array of valid CPE 2.3 names")
    channels = [("query", query.strip(), 1.0, ("description", "metadata", "patch", "aggregate")),
                ("poc", poc.strip(), 1.3, ("poc", "description", "aggregate")),
                ("component", (component or "").strip(), .8, ("component", "aggregate"))]
    channels = [channel for channel in channels if channel[1]]
    if not channels:
        raise ValueError("Provide query text, PoC text or a component")
    model_id = digest(encoder.manifest)
    if not store.db.execute("SELECT 1 FROM vector_models WHERE model_id=?", (model_id,)).fetchone():
        raise ValueError("No compatible index; run index with the same encoder first")
    query_vectors = {name: encode_query_text(encoder, text) for name, text, _, _ in channels}
    for vector in query_vectors.values():
        validate_vector(vector, encoder.manifest["dimension"])
    indexed_count = int(store.db.execute(
        "SELECT count(*) FROM vectors WHERE model_id=?", (model_id,)
    ).fetchone()[0])
    index_backend = "sqlite_exact"
    row_cursor = store.db.execute("""SELECT c.payload,v.vector,v.input_text FROM vectors v JOIN canonical c
        ON v.vuln_id=c.vuln_id AND v.revision=c.revision WHERE model_id=? ORDER BY v.vuln_id""", (model_id,))
    candidates: list[dict[str, Any]] = []

    def accepted_candidate(row: Any) -> dict[str, Any] | None:
        record = json.loads(row[0])
        accepted, version_state = matches(record, severity, component, version, cpes)
        if weakness and weakness.casefold() not in {str(x).casefold() for x in record["fields"].get("weaknesses") or []}:
            accepted = False
        if source and source.casefold() not in {str(x["source"]).casefold() for x in record.get("sources", [])}:
            accepted = False
        if accepted and record["status"] == "active":
            return {"record": record, "views": {}, "version_state": version_state,
                    "aggregate_vector": json.loads(row[1]), "aggregate_text": row[2]}
        return None

    if indexed_count > SCALABLE_SCAN_THRESHOLD:
        # Loading every payload and every multi-view vector at once can require several GB at
        # 100k+ records. Stream the aggregate view, retain a generous lexical/vector pool, then
        # run the existing multi-view scorer on that pool. The response names this backend
        # honestly: it is scalable two-stage retrieval, not exhaustive multi-view ranking.
        index_backend = "sqlite_two_stage"
        channel_vectors = [(query_vectors[name], set(tokens(text)), weight) for name, text, weight, _ in channels]
        pool_size = max(2_000, min(12_000, offset + top_k + 1_000))
        pool: list[tuple[float, str, dict[str, Any]]] = []
        weight_total = sum(weight for _, _, weight in channel_vectors)
        for row in row_cursor:
            candidate = accepted_candidate(row)
            if candidate is None:
                continue
            document_terms = set(tokens(candidate["aggregate_text"]))
            prescore = 0.0
            for query_vector, query_terms, weight in channel_vectors:
                lexical = len(query_terms & document_terms) / max(1, len(query_terms))
                prescore += weight * (cosine(query_vector, candidate["aggregate_vector"]) + .25 * lexical)
            prescore /= weight_total
            item = (prescore, candidate["record"]["vuln_id"], candidate)
            if len(pool) < pool_size:
                heapq.heappush(pool, item)
            elif item[:2] > pool[0][:2]:
                heapq.heapreplace(pool, item)
        candidates = [item[2] for item in pool]
    else:
        for row in row_cursor:
            candidate = accepted_candidate(row)
            if candidate is not None:
                candidates.append(candidate)
    if not candidates:
        return []  # Never remove user filters to manufacture results.
    views_by_record: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    keys = [(item["record"]["vuln_id"], item["record"]["revision"]) for item in candidates]
    for start in range(0, len(keys), 200):
        batch = keys[start:start + 200]
        placeholders = ",".join("(?,?)" for _ in batch)
        parameters: list[Any] = [model_id]
        for vuln_id, revision in batch:
            parameters.extend([vuln_id, revision])
        view_rows = store.db.execute(f"""SELECT vuln_id,revision,view_name,vector,input_text FROM vector_views
            WHERE model_id=? AND (vuln_id,revision) IN ({placeholders}) ORDER BY vuln_id,view_name""", parameters).fetchall()
        for item in view_rows:
            views_by_record.setdefault((item[0], item[1]), {})[item[2]] = {
                "vector": json.loads(item[3]), "text": item[4],
            }
    for candidate in candidates:
        record = candidate["record"]
        candidate["views"] = views_by_record.get((record["vuln_id"], record["revision"]), {})
        if not candidate["views"]:  # Compatibility with indexes created before multi-view/v1.
            candidate["views"] = {"aggregate": {"vector": candidate["aggregate_vector"],
                                                  "text": candidate["aggregate_text"]}}
    weight_total = sum(channel[2] for channel in channels)
    dense = {i: 0.0 for i in range(len(candidates))}
    sparse = {i: 0.0 for i in range(len(candidates))}
    breakdown: dict[int, dict[str, Any]] = {i: {} for i in range(len(candidates))}
    all_query_terms: set[str] = set()
    for channel_name, channel_text, weight, target_views in channels:
        query_vector = query_vectors[channel_name]
        query_terms = set(tokens(channel_text))
        all_query_terms.update(query_terms)
        documents = ["\n".join(candidate["views"][name]["text"] for name in target_views if name in candidate["views"])
                     for candidate in candidates]
        sparse_scores, _ = _bm25(query_terms, documents)
        for i, candidate in enumerate(candidates):
            view_scores = {}
            for name in target_views:
                if name in candidate["views"]:
                    stored = candidate["views"][name]["vector"]
                    validate_vector(stored, len(query_vector))
                    view_scores[name] = cosine(query_vector, stored)
            best_view = max(view_scores, key=view_scores.get) if view_scores else None
            channel_dense = view_scores[best_view] if best_view else 0.0
            dense[i] += weight * channel_dense / weight_total
            sparse[i] += weight * sparse_scores[i] / weight_total
            breakdown[i][channel_name] = {"weight": weight, "cosine": channel_dense,
                                           "bm25": sparse_scores[i], "best_view": best_view,
                                           "view_cosines": view_scores}
    if min_similarity is not None:
        keep = {i for i, value in dense.items() if value >= min_similarity}
        dense = {i: value for i, value in dense.items() if i in keep}
        sparse = {i: value for i, value in sparse.items() if i in keep}
    fused: Counter = Counter()
    score_sets = (dense, sparse) if mode == "hybrid" else (dense,) if mode == "dense" else (sparse,)
    for scores in score_sets:
        ranked = sorted(_rank(scores), key=lambda i: (-scores[i], candidates[i]["record"]["vuln_id"]))
        for rank, i in enumerate(ranked, start=1):
            fused[i] += 1 / (60 + rank)
    hits = []
    requested_ids = set(re.findall(r"\bCVE-\d{4}-\d{4,}\b", query.upper()))
    ranked_hits = sorted(fused, key=lambda i: (
        0 if candidates[i]["record"]["vuln_id"].upper() in requested_ids else 1,
        -fused[i], candidates[i]["record"]["vuln_id"],
    ))
    for rank, i in enumerate(ranked_hits[offset:offset + top_k], start=offset + 1):
        record = candidates[i]["record"]
        version_state = candidates[i]["version_state"]
        document = candidates[i]["views"].get("aggregate", {"text": ""})["text"]
        evidence = record["evidence"]
        best = sorted(evidence, key=lambda x: -len(all_query_terms.intersection(tokens(str(x.get("text") or "")))))
        hits.append({"vuln_id": record["vuln_id"], "title": record["fields"].get("title"), "severity": record["fields"].get("severity"),
                     "scores": {"cosine": dense[i], "bm25": sparse[i], "rrf": fused[i]},
                     "rank": rank, "score_breakdown": breakdown[i],
                     "matched_terms": sorted(all_query_terms.intersection(tokens(document))), "version_match": version_state,
                     "source_urls": record["references"], "evidence": [
                         {**x, **({"text": str(x["text"])[:600]} if x.get("text") is not None else {})} for x in best[:2]],
                     "conflicted_fields": sorted(record["conflicts"]), "record_revision": record["revision"], "model_id": model_id,
                     "filters": {"severity": severity, "weakness": weakness, "source": source,
                                 "component": component, "version": version, "cpes": cpes},
                     "retrieval_mode": mode, "semantic_model": encoder.manifest["semantic_model"],
                     "index_backend": index_backend})
    return hits


def record_similarity(store: Store, encoder: Encoder, left_id: str, right_id: str,
                      views: Iterable[str] | None = None) -> dict[str, Any]:
    model_id = digest(encoder.manifest)
    requested = set(views or [])
    if requested - {"aggregate", "description", "poc", "patch", "component", "metadata"}:
        raise ValueError("Unknown similarity view")

    def load(vuln_id: str) -> tuple[str, dict[str, list[float]]]:
        row = store.db.execute("SELECT vuln_id,revision FROM canonical WHERE vuln_id=? COLLATE NOCASE", (vuln_id,)).fetchone()
        if not row:
            raise ValueError(f"Unknown vulnerability: {vuln_id}")
        items = store.db.execute("""SELECT view_name,vector FROM vector_views
            WHERE model_id=? AND vuln_id=? AND revision=?""", (model_id, row[0], row[1])).fetchall()
        if not items:
            raise ValueError(f"No compatible index for vulnerability: {vuln_id}")
        return row[0], {item[0]: json.loads(item[1]) for item in items}

    left_name, left = load(left_id)
    right_name, right = load(right_id)
    common = sorted(set(left) & set(right) & requested if requested else set(left) & set(right))
    if not common:
        raise ValueError("The records have no requested indexed views in common")
    scores = {name: cosine(left[name], right[name]) for name in common}
    return {"left": left_name, "right": right_name, "model_id": model_id, "view_scores": scores,
            "aggregate_similarity": scores.get("aggregate"), "compared_views": common}


def evaluate(store: Store, encoder: Encoder, cases: list[dict[str, Any]], cutoffs: Iterable[int] = (1, 5, 10)) -> dict[str, Any]:
    ks = sorted(set(int(k) for k in cutoffs))
    if not ks or ks[0] < 1 or ks[-1] > 100:
        raise ValueError("Evaluation cutoffs must be between 1 and 100")
    if not cases:
        raise ValueError("Evaluation requires at least one case")
    recall = {k: 0.0 for k in ks}
    reciprocal_ranks, ndcgs, details, latencies = [], [], [], []
    for number, case in enumerate(cases, 1):
        relevant = {str(x).upper() for x in case.get("relevant", [])}
        if not relevant:
            raise ValueError(f"Evaluation case {number} requires relevant vulnerability IDs")
        arguments = {key: case[key] for key in ("query", "poc", "component", "version", "severity", "weakness", "source", "mode", "cpes") if key in case}
        started = time.perf_counter()
        hits = search(store, encoder, top_k=ks[-1], **arguments)
        latency_ms = (time.perf_counter() - started) * 1000
        latencies.append(latency_ms)
        returned = [hit["vuln_id"].upper() for hit in hits]
        first = next((rank for rank, vuln_id in enumerate(returned, 1) if vuln_id in relevant), None)
        reciprocal_ranks.append(1 / first if first else 0.0)
        ideal = sum(1 / math.log2(rank + 1) for rank in range(1, min(len(relevant), ks[-1]) + 1))
        dcg = sum(1 / math.log2(rank + 1) for rank, vuln_id in enumerate(returned, 1) if vuln_id in relevant)
        ndcgs.append(dcg / ideal if ideal else 0.0)
        for k in ks:
            recall[k] += len(relevant.intersection(returned[:k])) / len(relevant)
        details.append({"case": case.get("id", number), "relevant": sorted(relevant), "returned": returned,
                        "first_relevant_rank": first, "latency_ms": latency_ms})
    count = len(cases)
    ordered_latency = sorted(latencies)
    percentile = lambda value: ordered_latency[min(len(ordered_latency) - 1, math.ceil(value * len(ordered_latency)) - 1)]
    return {"cases": count, "cutoffs": ks, "recall": {f"@{k}": recall[k] / count for k in ks},
            "mrr": sum(reciprocal_ranks) / count, "ndcg": {f"@{ks[-1]}": sum(ndcgs) / count},
            "latency_ms": {"p50": percentile(.50), "p95": percentile(.95),
                           "min": ordered_latency[0], "max": ordered_latency[-1]},
            "model_id": digest(encoder.manifest), "details": details}
