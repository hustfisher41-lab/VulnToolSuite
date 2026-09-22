"""Shared, JSON-serializable contracts for source facts and canonical records."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any

SCHEMA = "vulntools/v1"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
FIELDS = ("title", "description", "components", "weaknesses", "severity", "attack_preconditions", "poc", "patch")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def unique(values: list[Any]) -> list[Any]:
    result, seen = [], set()
    for value in values:
        key = canonical_json(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


@dataclass
class SourceRecord:
    source: str
    source_id: str
    url: str
    raw: dict[str, Any]
    aliases: list[str] = field(default_factory=list)
    fields: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    status: str = "active"
    fetched_at: str = field(default_factory=now)
    source_updated_at: str | None = None

    def __post_init__(self) -> None:
        if self.source not in {"cve", "nvd", "avd", "cnnvd"}:
            raise ValueError(f"Unsupported source: {self.source}")
        if not self.source_id.strip():
            raise ValueError("source_id cannot be empty")
        if self.status not in {"active", "rejected"}:
            raise ValueError("status must be active or rejected")
        if self.source_updated_at:
            try:
                datetime.fromisoformat(self.source_updated_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("source_updated_at must be an ISO-8601 timestamp") from exc
        self.aliases = unique([x.strip().upper() for x in [self.source_id, *self.aliases] if x.strip()])
        cves = [x for x in self.aliases if CVE_PATTERN.fullmatch(x)]
        if len(cves) > 1:
            raise ValueError("A source record cannot assert multiple CVE identities")

    @property
    def vuln_id(self) -> str:
        return next((x for x in self.aliases if CVE_PATTERN.fullmatch(x)), f"{self.source.upper()}:{self.source_id.upper()}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
