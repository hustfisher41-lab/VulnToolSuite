"""Build auditable AVD/CNNVD exchange JSONL from official public catalogs.

This utility intentionally consumes only directly accessible official pages and
reports.  It does not solve WAF challenges, call undocumented APIs, or claim
that catalog rows contain the same fields as a vulnerability detail page.
"""
from __future__ import annotations

import argparse
import hashlib
from html import unescape
import json
from pathlib import Path
import re
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


AVD_HOST = "avd.aliyun.com"
CNNVD_HOSTS = {"www.cnnvd.org.cn", "cnnvd.org.cn"}
AVD_PATTERN = re.compile(r"AVD-\d{4}-\d+", re.I)
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CNNVD_PATTERN = re.compile(r"CNNVD\s*-\s*(\d{6})\s*-\s*(\d+)", re.I)
PDF_CVE_PATTERN = re.compile(r"CVE\s*-\s*(\d{4})\s*-\s*(\d{4,})", re.I)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _plain_html(value: str) -> str:
    value = re.sub(r"<script\b.*?</script>|<style\b.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", unescape(value)).strip()


def fetch_official_html(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != AVD_HOST:
        raise ValueError("AVD catalog URL must use the official HTTPS host")
    request = Request(
        url,
        headers={
            "User-Agent": "VulnToolSuite/0.2 (+public catalog importer)",
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    with urlopen(request, timeout=30) as response:
        final_url = response.geturl()
        final = urlparse(final_url)
        if final.scheme != "https" or final.hostname != AVD_HOST:
            raise ValueError("AVD catalog redirected outside the official host")
        body = response.read(5_000_001)
        if len(body) > 5_000_000:
            raise ValueError("AVD catalog response exceeds the size limit")
        charset = response.headers.get_content_charset() or "utf-8"
    html = body.decode(charset)
    if re.search(r'"_waf_[^"]+"|访问验证|安全验证', html):
        raise ValueError("AVD returned a WAF verification page")
    return html, _sha256(body)


def parse_avd_catalog(html: str, page_url: str, page_sha256: str) -> list[dict]:
    records: list[dict] = []
    for row_html in re.findall(r"<tr\b[^>]*>(.*?)</tr>", html, flags=re.I | re.S):
        source_match = AVD_PATTERN.search(row_html)
        if not source_match:
            continue
        source_id = source_match.group(0).upper()
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row_html, flags=re.I | re.S)
        if len(cells) < 4:
            raise ValueError(f"AVD catalog row {source_id} has an unexpected shape")
        title = _plain_html(cells[1])
        cve_match = CVE_PATTERN.search(row_html)
        cwe_match = re.search(r"CWE-\d+", row_html, flags=re.I)
        date_match = re.search(r"\d{4}-\d{2}-\d{2}", _plain_html(cells[3]))
        fields: dict[str, object] = {"title": title}
        if cwe_match:
            fields["weaknesses"] = [cwe_match.group(0).upper()]
        if date_match:
            fields["published_at"] = date_match.group(0) + "T00:00:00+08:00"
        detail_url = urljoin(page_url, "/detail?id=" + source_id)
        records.append(
            {
                "source_id": source_id,
                "url": detail_url,
                "aliases": [cve_match.group(0).upper()] if cve_match else [],
                "status": "active",
                "fields": fields,
                "references": [page_url],
                "provenance": {
                    "format": "avd-public-product-catalog/v1",
                    "catalog_page_url": page_url,
                    "catalog_page_sha256": page_sha256,
                    "catalog_cells": [_plain_html(cell) for cell in cells],
                    "detail_page_access": "waf_blocked_at_collection_time",
                },
            }
        )
    if not records:
        raise ValueError("AVD catalog did not contain recognizable rows")
    return records


def _row_title(text: str, source_start: int) -> str | None:
    prefix = text[:source_start]
    starts = list(re.finditer(r"(?m)^\s*(\d{1,3})\s+(?=\S)", prefix))
    if not starts:
        return None
    title = re.sub(r"\s+", " ", prefix[starts[-1].end():]).strip()
    if not title or len(title) > 180 or "CNNVD 编号" in title:
        return None
    return title


def parse_cnnvd_report(pdf_path: Path, report_url: str) -> list[dict]:
    parsed = urlparse(report_url)
    if parsed.scheme != "https" or parsed.hostname not in CNNVD_HOSTS:
        raise ValueError("CNNVD report URL must use an official HTTPS host")
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError("pypdf is required to parse CNNVD reports") from exc

    pdf_bytes = pdf_path.read_bytes()
    report_sha256 = _sha256(pdf_bytes)
    reader = PdfReader(pdf_path)
    by_id: dict[str, dict] = {}
    severity_map = {"超危": "critical", "高危": "high", "中危": "medium", "低危": "low"}
    for page_number, page in enumerate(reader.pages, 1):
        text = page.extract_text() or ""
        matches = list(CNNVD_PATTERN.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            evidence = text[match.start():end]
            cve_match = PDF_CVE_PATTERN.search(evidence)
            severity_match = re.search(r"(超危|高危|中危|低危)", evidence)
            if not cve_match or not severity_match:
                continue
            source_id = f"CNNVD-{match.group(1)}-{match.group(2)}"
            cve_id = f"CVE-{cve_match.group(1)}-{cve_match.group(2)}"
            fields: dict[str, object] = {"severity": severity_map[severity_match.group(1)]}
            title = _row_title(text, match.start())
            if title:
                fields["title"] = title
            record = {
                "source_id": source_id,
                "url": f"{report_url}#page={page_number}",
                "aliases": [cve_id],
                "status": "active",
                "fields": fields,
                "references": [report_url],
                "provenance": {
                    "format": "cnnvd-public-report-pdf/v1",
                    "report_url": report_url,
                    "report_sha256": report_sha256,
                    "page": page_number,
                    "evidence_text": re.sub(r"\s+", " ", evidence).strip(),
                },
            }
            previous = by_id.get(source_id)
            if previous is None or len(record["provenance"]["evidence_text"]) > len(previous["provenance"]["evidence_text"]):
                by_id[source_id] = record
    if not by_id:
        raise ValueError("CNNVD report did not contain recognizable CNNVD/CVE rows")
    return sorted(by_id.values(), key=lambda row: row["source_id"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--avd-page", action="append", default=[], help="Official AVD product catalog page URL")
    parser.add_argument("--cnnvd-pdf", type=Path)
    parser.add_argument("--cnnvd-url")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if bool(args.cnnvd_pdf) != bool(args.cnnvd_url):
        parser.error("--cnnvd-pdf and --cnnvd-url must be supplied together")
    if not args.avd_page and not args.cnnvd_pdf:
        parser.error("at least one AVD page or one CNNVD report is required")

    records: list[dict] = []
    for page_url in args.avd_page:
        html, page_sha256 = fetch_official_html(page_url)
        records.extend(parse_avd_catalog(html, page_url, page_sha256))
    if args.cnnvd_pdf:
        records.extend(parse_cnnvd_report(args.cnnvd_pdf, args.cnnvd_url))

    deduplicated: dict[tuple[str, str], dict] = {}
    for record in records:
        source = "avd" if record["source_id"].startswith("AVD-") else "cnnvd"
        deduplicated[(source, record["source_id"])] = {"source": source, **record}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as stream:
        for record in sorted(deduplicated.values(), key=lambda row: (row["source"], row["source_id"])):
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    counts = {source: sum(1 for row in deduplicated.values() if row["source"] == source) for source in ("avd", "cnnvd")}
    print(json.dumps({"output": str(args.output), "counts": counts}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
