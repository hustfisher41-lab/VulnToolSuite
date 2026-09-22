"""Offline feature baseline and optional local SentenceTransformer provider."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
from typing import Any, Protocol, Sequence

from .models import canonical_json, digest
from .storage import Store


def tokens(text: str) -> list[str]:
    terms = re.findall(r"[a-z0-9_]+(?:[.:-][a-z0-9_]+)*", text.lower())
    for phrase in re.findall(r"[\u3400-\u9fff]+", text):
        terms.extend(phrase)
        terms.extend(phrase[i:i + 2] for i in range(len(phrase) - 1))
    return terms


def input_text(record: dict[str, Any]) -> str:
    fields = record["fields"]
    parts = [record["vuln_id"], *record["aliases"]]
    for field in ("title", "description", "components", "weaknesses", "attack_preconditions", "poc", "patch", "image_text"):
        value = fields.get(field)
        if value:
            parts.append(f"{field}: {value if isinstance(value, str) else canonical_json(value)}")
    behaviors = sorted({
        behavior
        for evidence in record.get("evidence", [])
        for behavior in (evidence.get("representation") or {}).get("code_behavior", {}).get("behaviors", [])
    })
    if behaviors:
        parts.append("code_behaviors: " + " ".join(behaviors))
    return "\n".join(parts)


def view_texts(record: dict[str, Any]) -> dict[str, str]:
    """Build stable, separately searchable views of one canonical record."""
    fields = record["fields"]

    def rendered(name: str) -> str:
        value = fields.get(name)
        if value in (None, "", []):
            return ""
        return value if isinstance(value, str) else canonical_json(value)

    metadata = "\n".join(
        value for value in (
            f"vuln_id: {record['vuln_id']}",
            f"aliases: {' '.join(record['aliases'])}" if record.get("aliases") else "",
            f"title: {rendered('title')}" if rendered("title") else "",
            f"weaknesses: {rendered('weaknesses')}" if rendered("weaknesses") else "",
            f"severity: {rendered('severity')}" if rendered("severity") else "",
            f"attack_preconditions: {rendered('attack_preconditions')}" if rendered("attack_preconditions") else "",
        ) if value
    )
    behavior_items = []
    for evidence in record.get("evidence", []):
        code_behavior = (evidence.get("representation") or {}).get("code_behavior")
        if code_behavior:
            behavior_items.append(canonical_json(code_behavior))
    behaviors = "\n".join(sorted(set(behavior_items)))
    views = {
        "aggregate": input_text(record),
        "description": "\n".join(x for x in (rendered("title"), rendered("description"), rendered("image_text")) if x),
        "poc": rendered("poc"),
        "patch": rendered("patch"),
        "component": rendered("components"),
        "metadata": metadata,
        "behavior": behaviors,
    }
    return {name: text for name, text in views.items() if text.strip()}


def validate_vector(vector: list[float], dimension: int) -> None:
    if len(vector) != dimension or any(not math.isfinite(v) for v in vector):
        raise ValueError("Embedding has wrong dimension or non-finite values")


class Encoder(Protocol):
    manifest: dict[str, Any]
    def encode(self, text: str) -> list[float]: ...


def encode_query_text(encoder: Encoder, text: str) -> list[float]:
    """Encode retrieval input, using an instruction-aware query path when available."""
    method = getattr(encoder, "encode_query", None)
    return method(text) if callable(method) else encoder.encode(text)


def encode_document_texts(encoder: Encoder, texts: Sequence[str]) -> list[list[float]]:
    """Batch document encoding when supported, with compatibility for simple encoders."""
    if not texts:
        return []
    method = getattr(encoder, "encode_documents", None)
    vectors = method(list(texts)) if callable(method) else [encoder.encode(text) for text in texts]
    vectors = vectors.tolist() if hasattr(vectors, "tolist") else vectors
    if len(vectors) != len(texts):
        raise ValueError("Embedding provider returned the wrong number of vectors")
    output = [[float(value) for value in vector] for vector in vectors]
    for vector in output:
        validate_vector(vector, int(encoder.manifest["dimension"]))
    return output


class HashEncoder:
    """Signed feature hashing, NOT a trained semantic/multimodal model."""
    def __init__(self, dimension: int = 512):
        if dimension < 64:
            raise ValueError("Baseline dimension must be at least 64")
        self.manifest = {"provider": "feature-hash", "version": "1", "dimension": dimension,
                         "metric": "cosine", "preprocessing": "fields-en-cjk/v1", "semantic_model": False}

    def encode(self, text: str) -> list[float]:
        vector = [0.0] * self.manifest["dimension"]
        for token, count in Counter(tokens(text)).items():
            hashed = hashlib.sha256(token.encode("utf-8")).digest()
            index = int.from_bytes(hashed[:8], "big") % len(vector)
            vector[index] += (1 if hashed[8] % 2 else -1) * (1 + math.log(count))
        norm = math.sqrt(sum(x * x for x in vector))
        return [x / norm for x in vector] if norm else vector


class LocalSentenceEncoder:
    def __init__(self, model_path: str | Path):
        path = Path(model_path).resolve()
        if not path.is_dir():
            raise ValueError("model_path must be an existing local model directory")
        local_config: dict[str, Any] = {}
        local_config_path = path / "VULNTOOLS_MODEL.json"
        if local_config_path.is_file():
            local_config = json.loads(local_config_path.read_text(encoding="utf-8-sig"))
        max_sequence_length = int(local_config.get("max_sequence_length") or 1024)
        truncate_dimension = local_config.get("truncate_dimension")
        if max_sequence_length < 64:
            raise ValueError("Local model max_sequence_length must be at least 64")
        if truncate_dimension is not None and int(truncate_dimension) < 64:
            raise ValueError("Local model truncate_dimension must be at least 64")
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install the semantic extra to use a local model") from exc
        # Fingerprint local model bytes, so a weight change cannot silently reuse an index.
        files = sorted(
            x for x in path.rglob("*")
            if x.is_file() and ".cache" not in x.relative_to(path).parts
        )
        fingerprint = hashlib.sha256()
        for file in files:
            fingerprint.update(str(file.relative_to(path)).encode("utf-8"))
            with file.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    fingerprint.update(chunk)
        model_options = {"truncate_dim": int(truncate_dimension)} if truncate_dimension is not None else {}
        self.model = SentenceTransformer(
            str(path), local_files_only=True, trust_remote_code=False, **model_options,
        )
        self.model.max_seq_length = min(int(self.model.max_seq_length), max_sequence_length)
        prompts = getattr(self.model, "prompts", {}) or {}
        self.query_prompt_name = "query" if isinstance(prompts, dict) and prompts.get("query") else None
        query_prompt = prompts.get("query") if self.query_prompt_name else None
        self.manifest = {"provider": "sentence-transformers-local", "model_hash": fingerprint.hexdigest(),
                         "dimension": self.model.get_sentence_embedding_dimension(), "metric": "cosine",
                         "preprocessing": "fields-en-cjk/v3-query-aware-truncated", "semantic_model": True,
                         "max_sequence_length": self.model.max_seq_length,
                         "truncate_dimension": int(truncate_dimension) if truncate_dimension is not None else None,
                         "query_prompt_name": self.query_prompt_name, "query_prompt": query_prompt}

    def encode(self, text: str) -> list[float]:
        return self.encode_documents([text])[0]

    def encode_documents(self, texts: Sequence[str]) -> list[list[float]]:
        vectors = self.model.encode(list(texts), normalize_embeddings=True, show_progress_bar=False)
        output = vectors.tolist() if hasattr(vectors, "tolist") else vectors
        output = [[float(value) for value in vector] for vector in output]
        for vector in output:
            validate_vector(vector, self.manifest["dimension"])
        return output

    def encode_query(self, text: str) -> list[float]:
        kwargs = {"prompt_name": self.query_prompt_name} if self.query_prompt_name else {}
        vector = self.model.encode(text, normalize_embeddings=True, show_progress_bar=False, **kwargs).tolist()
        vector = [float(value) for value in vector]
        validate_vector(vector, self.manifest["dimension"])
        return vector


def cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Vectors have different dimensions")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return sum(a * b for a, b in zip(left, right)) / (left_norm * right_norm) if left_norm and right_norm else 0.0


class DomainAdapterEncoder:
    """A supervised diagonal metric adapter over a fixed local base encoder."""

    def __init__(self, base: Encoder, artifact: dict[str, Any]):
        if artifact.get("schema") != "vulntools/domain-adapter/v1":
            raise ValueError("Unsupported domain adapter schema")
        if artifact.get("base_manifest") != base.manifest:
            raise ValueError("Domain adapter base model contract mismatch")
        weights = artifact.get("weights")
        dimension = base.manifest["dimension"]
        if not isinstance(weights, list) or len(weights) != dimension:
            raise ValueError("Domain adapter has the wrong dimension")
        self.weights = [float(value) for value in weights]
        validate_vector(self.weights, dimension)
        if any(value <= 0 for value in self.weights):
            raise ValueError("Domain adapter weights must be positive")
        self.base = base
        self.artifact = artifact
        self.manifest = {
            "provider": "domain-metric-adapter", "version": "1",
            "base": base.manifest, "adapter_hash": digest(artifact),
            "dimension": dimension, "metric": "cosine",
            "preprocessing": base.manifest.get("preprocessing"),
            "semantic_model": bool(base.manifest.get("semantic_model")),
            "domain_trained": True,
        }

    @classmethod
    def load(cls, base: Encoder, path: str | Path) -> DomainAdapterEncoder:
        artifact = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return cls(base, artifact)

    def encode(self, text: str) -> list[float]:
        return self._adapt(self.base.encode(text))

    def _adapt(self, vector: list[float]) -> list[float]:
        adapted = [value * weight for value, weight in zip(vector, self.weights)]
        norm = math.sqrt(sum(value * value for value in adapted))
        return [value / norm for value in adapted] if norm else adapted

    def encode_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return [self._adapt(vector) for vector in encode_document_texts(self.base, texts)]

    def encode_query(self, text: str) -> list[float]:
        return self._adapt(encode_query_text(self.base, text))


def read_training_pairs(path: str | Path) -> list[dict[str, Any]]:
    pairs = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Embedding pair line {line_no}: invalid JSON") from exc
        if not isinstance(row, dict):
            raise ValueError(f"Embedding pair line {line_no}: expected an object")
        left = row.get("left")
        right = row.get("right")
        label = row.get("label")
        if not isinstance(left, str) or not left.strip() or not isinstance(right, str) or not right.strip():
            raise ValueError(f"Embedding pair line {line_no}: left and right must be nonempty strings")
        if type(label) not in {bool, int} or int(label) not in {0, 1}:
            raise ValueError(f"Embedding pair line {line_no}: label must be 0 or 1")
        pairs.append({"line": line_no, "left": left, "right": right, "label": int(label), "relation": str(row.get("relation") or "unspecified")})
    if not pairs or {pair["label"] for pair in pairs} != {0, 1}:
        raise ValueError("Embedding training requires at least one positive and one negative pair")
    return pairs


def generate_training_pairs(records: list[dict[str, Any]], max_negative_pairs: int = 10000) -> list[dict[str, Any]]:
    """Create evidence-backed cross-field positives and different-CWE negatives."""
    if type(max_negative_pairs) is not int or max_negative_pairs < 1:
        raise ValueError("max_negative_pairs must be a positive integer")
    active = [record for record in records if record.get("status") == "active"]
    pairs = []
    for record in active:
        views = view_texts(record)
        anchor = views.get("description") or views.get("aggregate")
        if not anchor:
            continue
        for view in ("poc", "patch", "component", "metadata"):
            if views.get(view):
                pairs.append({"left": anchor, "right": views[view], "label": 1, "relation": f"description_to_{view}", "vuln_ids": [record["vuln_id"]]})
    negative_count = 0
    for index, left_record in enumerate(active):
        left_views = view_texts(left_record)
        left_text = left_views.get("description") or left_views.get("aggregate")
        left_weaknesses = set(left_record.get("fields", {}).get("weaknesses") or [])
        for right_record in active[index + 1:]:
            if negative_count >= max_negative_pairs:
                break
            right_weaknesses = set(right_record.get("fields", {}).get("weaknesses") or [])
            if not left_weaknesses or not right_weaknesses or left_weaknesses & right_weaknesses:
                continue
            right_views = view_texts(right_record)
            right_text = right_views.get("description") or right_views.get("aggregate")
            if left_text and right_text:
                pairs.append({"left": left_text, "right": right_text, "label": 0, "relation": "different_weakness", "vuln_ids": [left_record["vuln_id"], right_record["vuln_id"]]})
                negative_count += 1
    return pairs


def fit_domain_adapter(
    base: Encoder,
    pairs: list[dict[str, Any]],
    output: str | Path,
    *,
    epochs: int = 8,
    learning_rate: float = 0.2,
    negative_margin: float = 0.2,
) -> dict[str, Any]:
    """Fit a reproducible supervised cosine metric without changing base-model files."""
    if type(epochs) is not int or not 1 <= epochs <= 1000:
        raise ValueError("epochs must be an integer between 1 and 1000")
    if not 0 < learning_rate <= 2:
        raise ValueError("learning_rate must be in (0, 2]")
    if not -1 <= negative_margin <= 1:
        raise ValueError("negative_margin must be between -1 and 1")
    if not pairs or {int(pair["label"]) for pair in pairs} != {0, 1}:
        raise ValueError("Embedding training requires positive and negative pairs")
    dimension = int(base.manifest["dimension"])
    encoded = [(base.encode(pair["left"]), base.encode(pair["right"]), int(pair["label"])) for pair in pairs]
    for left, right, _ in encoded:
        validate_vector(left, dimension)
        validate_vector(right, dimension)
    log_weights = [0.0] * dimension
    history = []
    for epoch in range(epochs):
        losses = []
        for left, right, label in encoded:
            q = [math.exp(value) for value in log_weights]
            a_norm_sq = sum(weight * value * value for weight, value in zip(q, left))
            b_norm_sq = sum(weight * value * value for weight, value in zip(q, right))
            denominator = math.sqrt(a_norm_sq * b_norm_sq)
            if not denominator:
                continue
            numerator = sum(weight * a * b for weight, a, b in zip(q, left, right))
            similarity = numerator / denominator
            active_loss = label == 1 or similarity > negative_margin
            losses.append(1 - similarity if label == 1 else max(0.0, similarity - negative_margin))
            if not active_loss:
                continue
            direction = 1.0 if label == 1 else -1.0
            for index in range(dimension):
                derivative = q[index] * (
                    left[index] * right[index] / denominator
                    - 0.5 * similarity * (left[index] ** 2 / a_norm_sq + right[index] ** 2 / b_norm_sq)
                )
                log_weights[index] = max(-4.0, min(4.0, log_weights[index] + learning_rate * direction * derivative))
        history.append({"epoch": epoch + 1, "mean_loss": statistics.fmean(losses) if losses else 0.0})
    weights = [math.exp(value / 2) for value in log_weights]
    artifact = {
        "schema": "vulntools/domain-adapter/v1", "base_manifest": base.manifest,
        "weights": weights,
        "training": {
            "objective": "supervised-diagonal-cosine/v1", "pairs": len(pairs),
            "positive_pairs": sum(pair["label"] == 1 for pair in pairs),
            "negative_pairs": sum(pair["label"] == 0 for pair in pairs),
            "epochs": epochs, "learning_rate": learning_rate, "negative_margin": negative_margin,
            "history": history,
        },
    }
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(artifact, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return {"output": str(target.resolve()), "adapter": DomainAdapterEncoder(base, artifact).manifest, "training": artifact["training"]}


def classify_text(records: list[dict[str, Any]], encoder: Encoder, text: str, top_k: int = 5) -> list[dict[str, Any]]:
    """Rank weakness labels by centroids of labeled vulnerability descriptions."""
    if not text.strip():
        raise ValueError("Classification text cannot be empty")
    if type(top_k) is not int or top_k < 1:
        raise ValueError("top_k must be positive")
    grouped: dict[str, list[tuple[str, list[float]]]] = {}
    for record in records:
        if record.get("status") != "active":
            continue
        description = view_texts(record).get("description")
        if not description:
            continue
        vector = encoder.encode(description)
        for label in record.get("fields", {}).get("weaknesses") or []:
            grouped.setdefault(str(label), []).append((record["vuln_id"], vector))
    query = encode_query_text(encoder, text)
    results = []
    for label, examples in grouped.items():
        centroid = [statistics.fmean(vector[index] for _, vector in examples) for index in range(len(query))]
        results.append({"label": label, "score": cosine(query, centroid), "support": len(examples), "examples": [vuln_id for vuln_id, _ in examples]})
    return sorted(results, key=lambda item: (-item["score"], item["label"]))[:top_k]


def cluster_records(records: list[dict[str, Any]], encoder: Encoder, clusters: int = 8, iterations: int = 25) -> dict[str, Any]:
    """Deterministic spherical k-means with medoids and source record IDs."""
    active = [record for record in records if record.get("status") == "active"]
    if not active:
        return {"clusters": [], "records": 0}
    if type(clusters) is not int or not 1 <= clusters <= len(active):
        raise ValueError("clusters must be between 1 and the active record count")
    vectors = [encoder.encode(input_text(record)) for record in active]
    centroids = [vectors[index * len(vectors) // clusters][:] for index in range(clusters)]
    assignments = [-1] * len(vectors)
    for _ in range(iterations):
        new_assignments = [max(range(clusters), key=lambda index: cosine(vector, centroids[index])) for vector in vectors]
        if new_assignments == assignments:
            break
        assignments = new_assignments
        for cluster_id in range(clusters):
            members = [vectors[index] for index, assigned in enumerate(assignments) if assigned == cluster_id]
            if members:
                center = [statistics.fmean(vector[index] for vector in members) for index in range(len(vectors[0]))]
                norm = math.sqrt(sum(value * value for value in center))
                centroids[cluster_id] = [value / norm for value in center] if norm else center
    output = []
    for cluster_id in range(clusters):
        indexes = [index for index, assigned in enumerate(assignments) if assigned == cluster_id]
        if not indexes:
            continue
        medoid = max(indexes, key=lambda index: cosine(vectors[index], centroids[cluster_id]))
        weakness_counts = Counter(weakness for index in indexes for weakness in active[index].get("fields", {}).get("weaknesses") or ["unknown"])
        output.append({
            "cluster": cluster_id, "size": len(indexes), "medoid": active[medoid]["vuln_id"],
            "members": [active[index]["vuln_id"] for index in indexes], "weaknesses": dict(weakness_counts),
            "cohesion": statistics.fmean(cosine(vectors[index], centroids[cluster_id]) for index in indexes),
        })
    return {"records": len(active), "requested_clusters": clusters, "clusters": output, "model": encoder.manifest}


def index_records(
    store: Store,
    encoder: Encoder,
    *,
    batch_size: int = 32,
    max_records: int | None = None,
) -> dict[str, Any]:
    if type(batch_size) is not int or batch_size < 1:
        raise ValueError("batch_size must be a positive integer")
    if max_records is not None and (type(max_records) is not int or max_records < 1):
        raise ValueError("max_records must be a positive integer")
    manifest = encoder.manifest
    model_id = digest(manifest)
    changed, skipped, indexed_views = 0, 0, 0
    with store.db:
        previous = store.db.execute("SELECT manifest FROM vector_models WHERE model_id=?", (model_id,)).fetchone()
        if previous and json.loads(previous[0]) != manifest:
            raise ValueError("Index model contract mismatch")
        store.db.execute("INSERT OR IGNORE INTO vector_models VALUES (?,?)", (model_id, canonical_json(manifest)))
        pending: list[tuple[dict[str, Any], dict[str, str]]] = []
        pending_texts = 0

        def flush() -> None:
            nonlocal changed, indexed_views, pending, pending_texts
            if not pending:
                return
            names_and_texts = [
                (name, text)
                for _, views in pending
                for name, text in views.items()
            ]
            vectors = encode_document_texts(encoder, [text for _, text in names_and_texts])
            cursor = 0
            for record, views in pending:
                encoded = {}
                for name in views:
                    encoded[name] = vectors[cursor]
                    cursor += 1
                store.db.execute("DELETE FROM vector_views WHERE model_id=? AND vuln_id=?", (model_id, record["vuln_id"]))
                for name, text in views.items():
                    store.db.execute("INSERT INTO vector_views VALUES (?,?,?,?,?,?)",
                                     (model_id, record["vuln_id"], record["revision"], name,
                                      canonical_json(encoded[name]), text))
                    indexed_views += 1
                store.db.execute("INSERT OR REPLACE INTO vectors VALUES (?,?,?,?,?)",
                                 (model_id, record["vuln_id"], record["revision"],
                                  canonical_json(encoded["aggregate"]), views["aggregate"]))
                changed += 1
            pending = []
            pending_texts = 0

        for record in store.iter_records():
            if record["status"] != "active":
                store.db.execute("DELETE FROM vectors WHERE vuln_id=?", (record["vuln_id"],))
                store.db.execute("DELETE FROM vector_views WHERE vuln_id=?", (record["vuln_id"],))
                continue
            views = view_texts(record)
            previous = store.db.execute("SELECT revision FROM vectors WHERE model_id=? AND vuln_id=?", (model_id, record["vuln_id"])).fetchone()
            existing_views = {row[0]: row[1] for row in store.db.execute(
                "SELECT view_name,revision FROM vector_views WHERE model_id=? AND vuln_id=?",
                (model_id, record["vuln_id"]),
            )}
            if (previous and previous[0] == record["revision"] and set(existing_views) == set(views)
                    and all(revision == record["revision"] for revision in existing_views.values())):
                skipped += 1
                continue
            if max_records is not None and changed + len(pending) >= max_records:
                break
            pending.append((record, views))
            pending_texts += len(views)
            if pending_texts >= batch_size:
                flush()
        flush()
        remaining = int(store.db.execute("""SELECT count(*) FROM canonical c
            LEFT JOIN vectors v ON v.vuln_id=c.vuln_id AND v.revision=c.revision AND v.model_id=?
            WHERE json_extract(c.payload,'$.status')='active' AND v.vuln_id IS NULL""", (model_id,)).fetchone()[0])
    return {"model_id": model_id, "manifest": manifest, "indexed": changed, "skipped": skipped,
            "indexed_views": indexed_views, "remaining_records": remaining,
            "complete": remaining == 0, "view_schema": "multiview/v1"}
