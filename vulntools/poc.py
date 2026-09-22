"""Static PoC artifact importers. Collected code is never executed."""
from __future__ import annotations

import csv
from pathlib import Path
import re
from typing import Any

from .models import CVE_PATTERN, digest
from .storage import Store


POC_SOURCES = {"nuclei", "exploitdb", "metasploit", "github"}
TEXT_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".html", ".java", ".js", ".json", ".md",
    ".php", ".pl", ".ps1", ".py", ".rb", ".rs", ".sh", ".txt", ".xml", ".yaml", ".yml",
}
LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cs": "csharp", ".go": "go",
    ".html": "html", ".java": "java", ".js": "javascript", ".json": "json",
    ".md": "markdown", ".php": "php", ".pl": "perl", ".ps1": "powershell",
    ".py": "python", ".rb": "ruby", ".rs": "rust", ".sh": "shell", ".xml": "xml",
    ".yaml": "yaml", ".yml": "yaml",
}


def _read_text(path: Path, max_bytes: int) -> tuple[str | None, str | None]:
    try:
        size = path.stat().st_size
    except OSError:
        return None, "blocked_or_unreadable"
    if size > max_bytes:
        return None, "too_large"
    try:
        raw = path.read_bytes()
    except OSError:
        return None, "blocked_or_unreadable"
    if b"\x00" in raw:
        return None, "binary"
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(encoding), None
        except UnicodeDecodeError:
            continue
    return None, "decode_error"


def _cves(text: str) -> list[str]:
    return sorted({item.upper() for item in CVE_PATTERN.findall(text)})


def _yaml_scalar(text: str, key: str) -> str:
    match = re.search(rf"(?m)^\s*{re.escape(key)}\s*:\s*['\"]?([^\r\n'\"]+)", text)
    return match.group(1).strip() if match else ""


def _artifact(
    *, source: str, source_item_id: str, artifact_type: str, title: str, source_url: str,
    content: str, cve_ids: list[str], local_path: str, commit_ref: str | None,
    license_name: str | None, metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if source not in POC_SOURCES:
        raise ValueError(f"Unsupported PoC source: {source}")
    return {
        "artifact_id": digest([source, source_item_id]),
        "source": source,
        "source_item_id": source_item_id,
        "artifact_type": artifact_type,
        "title": title,
        "source_url": source_url,
        "commit_ref": commit_ref,
        "local_path": local_path,
        "language": LANGUAGES.get(Path(local_path).suffix.casefold(),
                                   LANGUAGES.get(Path(source_item_id).suffix.casefold(), "text")),
        "license": license_name,
        "review_status": "candidate",
        "content": content,
        "cve_ids": cve_ids,
        "link_relation": "claims_to_reproduce" if artifact_type == "exploit_code" else "detects",
        "link_confidence": 0.90 if source == "exploitdb" else 0.85,
        "metadata": metadata or {},
    }


def import_nuclei_directory(
    store: Store,
    directory: str | Path,
    *,
    commit_ref: str | None = None,
    license_name: str | None = "MIT",
    max_files: int | None = None,
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Import CVE-linked Nuclei YAML as detection templates, never exploit code."""
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError("Nuclei template directory does not exist")
    if max_files is not None and max_files < 1:
        raise ValueError("max_files must be positive")
    files = sorted([*root.rglob("*.yaml"), *root.rglob("*.yml")])
    artifacts, skipped = [], {"no_cve": 0, "too_large": 0, "binary": 0,
                              "decode_error": 0, "blocked_or_unreadable": 0}
    scanned = 0
    for path in files:
        if max_files is not None and scanned >= max_files:
            break
        scanned += 1
        text, reason = _read_text(path, max_bytes)
        if reason:
            skipped[reason] += 1
            continue
        assert text is not None
        cve_ids = _cves(text)
        if not cve_ids:
            skipped["no_cve"] += 1
            continue
        relative = path.relative_to(root).as_posix()
        template_id = _yaml_scalar(text, "id") or relative
        artifacts.append(_artifact(
            source="nuclei", source_item_id=relative, artifact_type="detection_template",
            title=_yaml_scalar(text, "name") or template_id,
            source_url=f"https://github.com/projectdiscovery/nuclei-templates/blob/{commit_ref or 'main'}/{relative}",
            content=text, cve_ids=cve_ids, local_path=str(path), commit_ref=commit_ref,
            license_name=license_name,
            metadata={"template_id": template_id, "severity": _yaml_scalar(text, "severity"),
                      "tags": _yaml_scalar(text, "tags")},
        ))
    saved = store.save_poc_artifacts(artifacts)
    return {"source": "nuclei", "root": str(root), "discovered_files": len(files),
            "scanned_files": scanned, "matched_files": len(artifacts), "skipped": skipped, **saved}


def _find_exploitdb_csv(root: Path) -> Path:
    candidates = [root / "files_exploits.csv", root / "files_shellcodes.csv"]
    match = next((path for path in candidates if path.is_file()), None)
    if match:
        return match
    matches = sorted(root.rglob("files_exploits.csv"))
    if not matches:
        raise ValueError("Exploit-DB directory does not contain files_exploits.csv")
    return matches[0]


def import_exploitdb_directory(
    store: Store,
    directory: str | Path,
    *,
    commit_ref: str | None = None,
    license_name: str | None = None,
    max_files: int | None = None,
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Import CVE-labelled Exploit-DB source files as unverified exploit candidates."""
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError("Exploit-DB directory does not exist")
    if max_files is not None and max_files < 1:
        raise ValueError("max_files must be positive")
    index = _find_exploitdb_csv(root)
    artifacts, skipped = [], {"no_cve": 0, "missing_file": 0, "too_large": 0,
                              "binary": 0, "decode_error": 0, "blocked_or_unreadable": 0}
    scanned = 0
    with index.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if max_files is not None and scanned >= max_files:
                break
            scanned += 1
            source_id = str(row.get("id") or "").strip()
            relative = str(row.get("file") or "").replace("\\", "/").lstrip("/")
            cve_ids = _cves(" ".join(str(row.get(key) or "") for key in ("codes", "aliases", "description")))
            if not cve_ids:
                skipped["no_cve"] += 1
                continue
            path = root / relative
            if not path.is_file():
                skipped["missing_file"] += 1
                continue
            text, reason = _read_text(path, max_bytes)
            if reason:
                skipped[reason] += 1
                continue
            assert text is not None
            artifacts.append(_artifact(
                source="exploitdb", source_item_id=source_id or relative, artifact_type="exploit_code",
                title=str(row.get("description") or source_id or relative),
                source_url=f"https://www.exploit-db.com/exploits/{source_id}" if source_id else str(row.get("source_url") or ""),
                content=text, cve_ids=cve_ids, local_path=str(path), commit_ref=commit_ref,
                license_name=license_name,
                metadata={key: row.get(key) for key in ("author", "date_published", "type", "platform", "verified", "tags")},
            ))
    saved = store.save_poc_artifacts(artifacts)
    return {"source": "exploitdb", "root": str(root), "index": str(index),
            "scanned_rows": scanned, "matched_files": len(artifacts), "skipped": skipped, **saved}


def import_poc_directory(store: Store, source: str, directory: str | Path, **kwargs: Any) -> dict[str, Any]:
    if source == "nuclei":
        if kwargs.get("license_name") is None:
            kwargs["license_name"] = "MIT"
        return import_nuclei_directory(store, directory, **kwargs)
    if source == "exploitdb":
        return import_exploitdb_directory(store, directory, **kwargs)
    raise ValueError("Directory importer currently supports nuclei or exploitdb")
