"""Strict parsers for CVE JSON 5, NVD 2, and AVD/CNNVD public pages or exports."""
from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from .models import CVE_PATTERN, SourceRecord, unique


def descriptions(items: list[dict[str, Any]]) -> str:
    return "\n".join(str(x["value"]) for x in items if x.get("value"))


def parse_cve(data: dict[str, Any]) -> SourceRecord:
    meta = data["cveMetadata"]
    cve_id = str(meta["cveId"]).upper()
    if not CVE_PATTERN.fullmatch(cve_id):
        raise ValueError("Invalid CVE identifier")
    container_data = data.get("containers", {})
    cna = container_data.get("cna", {})
    containers = [cna, *container_data.get("adp", [])]
    components = []
    for container in containers:
        for item in container.get("affected", []):
            component = {"vendor": item.get("vendor", ""), "name": item.get("product") or item.get("packageName", ""),
                         "versions": item.get("versions", []), "default_status": item.get("defaultStatus", "unknown")}
            component.update({key: item[key] for key in ("packageName", "packageURL", "collectionURL", "cpes", "modules") if key in item})
            components.append(component)
    weaknesses = []
    for container in containers:
        for problem in container.get("problemTypes", []):
            for desc in problem.get("descriptions", []):
                if desc.get("cweId"):
                    weaknesses.append(desc["cweId"])
    fields: dict[str, Any] = {"title": cna.get("title", ""),
                              "description": descriptions([item for container in containers for item in container.get("descriptions", [])]),
                              "components": unique(components), "weaknesses": unique(weaknesses),
                              "published_at": meta.get("datePublished"), "updated_at": meta.get("dateUpdated")}
    cvss_candidates = []
    for container in containers:
        for metric in container.get("metrics", []):
            for key, value in metric.items():
                if key.lower().startswith("cvss") and isinstance(value, dict):
                    cvss_candidates.append((float(value.get("version", 0) or 0), value))
                elif key == "other" and isinstance(value, dict) and value.get("type") == "ssvc":
                    fields["ssvc"] = value.get("content")
    if cvss_candidates:
        fields["cvss"] = max(cvss_candidates, key=lambda item: item[0])[1]
        if fields["cvss"].get("baseSeverity"):
            fields["severity"] = fields["cvss"]["baseSeverity"].lower()
    references = unique([item["url"] for container in containers for item in container.get("references", []) if item.get("url")])
    return SourceRecord("cve", cve_id, f"https://www.cve.org/CVERecord?id={cve_id}", data,
                        fields=fields, references=references,
                        status="rejected" if meta.get("state") == "REJECTED" else "active",
                        source_updated_at=meta.get("dateUpdated"))


def parse_nvd(data: dict[str, Any]) -> SourceRecord:
    cve = data.get("cve", data)
    cve_id = str(cve["id"]).upper()
    if not CVE_PATTERN.fullmatch(cve_id):
        raise ValueError("Invalid NVD CVE identifier")
    components = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                cpe = match.get("criteria", "")
                # Preserve the original applicability tree; this projection is for discovery.
                parts = re.split(r"(?<!\\):", cpe)
                if len(parts) >= 6:
                    version = {"version": parts[5], "status": "affected", "versionType": "unknown"}
                    version.update({k: v for k, v in match.items() if k.startswith("version")})
                    components.append({"vendor": parts[3], "name": parts[4], "versions": [version], "cpe": cpe, "default_status": "unknown"})
            for key in ("nodes", "children"):
                walk(node.get(key, []))

    walk(cve.get("configurations", []))
    weaknesses = [d["value"] for item in cve.get("weaknesses", []) for d in item.get("description", []) if re.fullmatch(r"CWE-\d+", d.get("value", ""))]
    for item in cve.get("affected", []):
        components.append({"vendor": item.get("vendor", ""), "name": item.get("product") or item.get("packageName", ""),
                           "versions": item.get("versions", []), "default_status": item.get("defaultStatus", "unknown"),
                           **{key: item[key] for key in ("packageName", "packageURL", "collectionURL", "cpes") if key in item}})
    fields: dict[str, Any] = {"description": descriptions(cve.get("descriptions", [])), "components": unique(components),
                              "weaknesses": unique(weaknesses), "applicability": cve.get("configurations", []),
                              "published_at": cve.get("published"), "updated_at": cve.get("lastModified"),
                              "source_identifier": cve.get("sourceIdentifier")}
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0]
            fields["cvss"] = metric.get("cvssData", {})
            fields["severity"] = (fields["cvss"].get("baseSeverity") or metric.get("baseSeverity") or "").lower()
            break
    return SourceRecord("nvd", cve_id, f"https://nvd.nist.gov/vuln/detail/{cve_id}", data,
                        fields=fields, references=[x["url"] for x in cve.get("references", []) if x.get("url")],
                        status="rejected" if cve.get("vulnStatus") == "Rejected" else "active",
                        source_updated_at=cve.get("lastModified"))


def parse_exchange(source: str, data: dict[str, Any]) -> SourceRecord:
    """Our exchange format: source_id, url, aliases, fields, references, status."""
    if not isinstance(data.get("fields"), dict):
        raise ValueError(f"{source} export requires a fields object; see docs/exchange-format.md")
    return SourceRecord(source, str(data["source_id"]), str(data["url"]), data,
                        aliases=data.get("aliases", []), fields=data["fields"],
                        references=data.get("references", []), status=data.get("status", "active"),
                        source_updated_at=data.get("source_updated_at"))


class _PublicPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.capture: str | None = None
        self.buffer: list[str] = []
        self.blocks: list[tuple[str, str]] = []
        self.text: list[str] = []
        self.links: list[str] = []
        self.meta: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1
            return
        if self.hidden:
            return
        if tag in {"title", "h1", "h2", "dt", "dd", "th", "td"} and self.capture is None:
            self.capture, self.buffer = tag, []
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        if tag == "meta" and attributes.get("content"):
            key = attributes.get("property") or attributes.get("name")
            if key:
                self.meta[key.casefold()] = attributes["content"].strip()

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self.hidden:
            self.hidden -= 1
            return
        if not self.hidden and self.capture == tag:
            value = re.sub(r"\s+", " ", " ".join(self.buffer)).strip()
            if value:
                self.blocks.append((tag, value))
            self.capture, self.buffer = None, []

    def handle_data(self, data: str) -> None:
        if self.hidden:
            return
        value = re.sub(r"\s+", " ", data).strip()
        if value:
            self.text.append(value)
            if self.capture:
                self.buffer.append(value)


def _page_pairs(blocks: list[tuple[str, str]]) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for index, (tag, label) in enumerate(blocks[:-1]):
        next_tag, value = blocks[index + 1]
        if (tag, next_tag) in {("dt", "dd"), ("th", "td")}:
            pairs[re.sub(r"[：:\s]+$", "", label).casefold()] = value
    return pairs


def _first_pair(pairs: dict[str, str], labels: tuple[str, ...]) -> str:
    for key, value in pairs.items():
        if any(label.casefold() in key for label in labels):
            return value
    return ""


def _page_timestamp(value: str) -> str | None:
    match = re.search(r"\d{4}-\d{1,2}-\d{1,2}(?:[T ]\d{1,2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?", value)
    if not match:
        return None
    timestamp = match[0].replace(" ", "T")
    if "T" not in timestamp:
        timestamp += "T00:00:00Z"
    elif not re.search(r"(?:Z|[+-]\d{2}:?\d{2})$", timestamp):
        timestamp += "+08:00"
    return timestamp


def parse_public_page(source: str, html: str, url: str, identifier: str | None = None) -> SourceRecord:
    """Parse one public AVD/CNNVD detail page without bypassing WAF or authentication."""
    if source not in {"avd", "cnnvd"}:
        raise ValueError("Public page parsing supports avd or cnnvd")
    if re.search(r'"_waf_[^"]+"', html) or "访问验证" in html or "安全验证" in html:
        raise ValueError(f"{source.upper()} returned a WAF verification page")
    parser = _PublicPageParser()
    parser.feed(html)
    visible = "\n".join(parser.text)
    id_pattern = re.compile(r"AVD-\d{4}-\d+", re.I) if source == "avd" else re.compile(r"CNNVD-\d{6}-\d+", re.I)
    source_ids = unique([match.upper() for match in id_pattern.findall(visible)])
    if len(source_ids) != 1:
        raise ValueError(f"Expected one {source.upper()} identifier on a vulnerability detail page")
    source_id = source_ids[0]
    if identifier and id_pattern.fullmatch(identifier) and source_id.casefold() != identifier.casefold():
        raise ValueError("Detail page identifier does not match the requested identifier")
    aliases = unique([match.upper() for match in CVE_PATTERN.findall(visible)])
    if len(aliases) > 1:
        raise ValueError("Detail page asserts multiple CVE identities")
    pairs = _page_pairs(parser.blocks)
    title = next((value for tag, value in parser.blocks if tag == "h1"), "") or parser.meta.get("og:title", "")
    if not title:
        title = next((value for tag, value in parser.blocks if tag == "title"), "")
    description = _first_pair(pairs, ("漏洞描述", "漏洞详情", "漏洞简介", "description"))
    if not description:
        description = parser.meta.get("description", "") or parser.meta.get("og:description", "")
    severity_text = _first_pair(pairs, ("危害等级", "风险等级", "severity"))
    severity = next((normalized for label, normalized in (("超危", "critical"), ("严重", "critical"),
                    ("高危", "high"), ("中危", "medium"), ("低危", "low")) if label in severity_text), "")
    weaknesses = unique(re.findall(r"CWE-\d+", visible, re.I))
    product = _first_pair(pairs, ("影响产品", "受影响产品", "影响组件", "产品名称", "affected product"))
    fields: dict[str, Any] = {"title": title, "description": description,
                              "components": [{"vendor": "", "name": product, "versions": [], "default_status": "unknown"}] if product else [],
                              "weaknesses": [item.upper() for item in weaknesses]}
    if severity:
        fields["severity"] = severity
    published = _first_pair(pairs, ("披露时间", "发布时间", "发布日期", "published"))
    updated = _first_pair(pairs, ("更新时间", "更新日期", "last modified"))
    if published:
        fields["published_at"] = _page_timestamp(published)
    source_updated_at = _page_timestamp(updated or published)
    if source_updated_at:
        fields["updated_at"] = source_updated_at
    references = []
    for link in parser.links:
        absolute = urljoin(url, link)
        if urlparse(absolute).scheme in {"http", "https"}:
            references.append(absolute)
    if not title and not description:
        raise ValueError(f"{source.upper()} page did not contain recognizable vulnerability fields")
    raw = {"format": "public-html/v1", "url": url, "html": html}
    return SourceRecord(source, source_id, url, raw, aliases=aliases, fields=fields,
                        references=unique(references), source_updated_at=source_updated_at)


def parse(source: str, payload: Any) -> list[SourceRecord]:
    if isinstance(payload, list):
        return [record for item in payload for record in parse(source, item)]
    if not isinstance(payload, dict):
        raise ValueError("Input must be a JSON object or array")
    if source == "cve":
        return [parse_cve(payload)]
    if source == "nvd":
        rows = payload.get("vulnerabilities", [payload])
        return [parse_nvd(row) for row in rows]
    if source in {"avd", "cnnvd"}:
        return [parse_exchange(source, payload)]
    raise ValueError(f"Unsupported source: {source}")


def read_file(source: str, path: str | Path) -> list[SourceRecord]:
    path = Path(path)
    if path.is_dir():
        records = []
        for item in sorted(path.rglob("*.json")):
            if item.name not in {"delta.json", "deltaLog.json"}:
                records.extend(parse(source, json.loads(item.read_text(encoding="utf-8-sig"))))
        return records
    content = path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() in {".html", ".htm"}:
        return [parse_public_page(source, content, path.resolve().as_uri())]
    if path.suffix.lower() == ".jsonl":
        return [r for line in content.splitlines() if line.strip() for r in parse(source, json.loads(line))]
    return parse(source, json.loads(content))


def fetch_cve(source: str, cve_id: str, *, api_key: str | None = None) -> list[SourceRecord]:
    """Compatibility wrapper for one official CVE/NVD record."""
    from .collection import fetch_record
    return [fetch_record(source, cve_id, api_key=api_key)]
