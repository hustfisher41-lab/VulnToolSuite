"""Offline native image embeddings from an explicitly supplied local model."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Protocol

from .embedding import validate_vector
from .models import digest


VISION_SCHEMA = "vulntools/vision-embedding/v1"


class VisionEncoder(Protocol):
    manifest: dict[str, Any]
    def encode_image(self, path: str | Path) -> list[float]: ...


def _model_fingerprint(path: Path) -> str:
    fingerprint = hashlib.sha256()
    for file in sorted(item for item in path.rglob("*") if item.is_file()):
        fingerprint.update(str(file.relative_to(path)).encode("utf-8"))
        with file.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                fingerprint.update(chunk)
    return fingerprint.hexdigest()


class LocalVisionEncoder:
    """SentenceTransformers-compatible image encoder loaded from local files only."""

    def __init__(self, model_path: str | Path):
        path = Path(model_path).resolve()
        if not path.is_dir():
            raise ValueError("vision model_path must be an existing local model directory")
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install the vision extra to use a local image model") from exc
        self.model = SentenceTransformer(str(path), local_files_only=True, trust_remote_code=False)
        dimension = self.model.get_sentence_embedding_dimension()
        if not isinstance(dimension, int) or dimension < 1:
            raise ValueError("Local vision model did not declare an embedding dimension")
        self.manifest = {
            "provider": "sentence-transformers-local-vision", "model_hash": _model_fingerprint(path),
            "dimension": dimension, "metric": "cosine", "modality": "image",
            "native_vision_model": True,
        }

    def encode_image(self, path: str | Path) -> list[float]:
        try:
            from PIL import Image
        except ImportError as exc:
            raise RuntimeError("Install the vision extra to decode images") from exc
        with Image.open(path) as picture:
            picture.load()
            encoded = self.model.encode(picture.convert("RGB"), normalize_embeddings=True, show_progress_bar=False)
        vector = encoded.tolist() if hasattr(encoded, "tolist") else list(encoded)
        vector = [float(value) for value in vector]
        validate_vector(vector, self.manifest["dimension"])
        return vector


def encode_image_artifact(path: str | Path, encoder: VisionEncoder) -> dict[str, Any]:
    image = Path(path).resolve()
    if not image.is_file():
        raise ValueError("Image input must be an existing file")
    manifest = dict(encoder.manifest)
    if manifest.get("modality") != "image" or not manifest.get("native_vision_model"):
        raise ValueError("Vision encoder manifest must declare native image support")
    dimension = manifest.get("dimension")
    if not isinstance(dimension, int) or dimension < 1:
        raise ValueError("Vision encoder manifest has an invalid dimension")
    vector = [float(value) for value in encoder.encode_image(image)]
    validate_vector(vector, dimension)
    model_id = digest(manifest)
    return {
        "schema": VISION_SCHEMA, "modality": "image_embedding",
        "path": str(image), "content_hash": hashlib.sha256(image.read_bytes()).hexdigest(),
        "model_id": model_id, "model": manifest, "dimension": dimension,
        "embedding_hash": digest(vector), "embedding": vector,
    }
