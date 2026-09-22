"""Resumable, rate-limited collection jobs for the four vulnerability sources."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

from .collectors import parse, parse_public_page
from .models import CVE_PATTERN
from .storage import Store


CVE_RAW_ROOT = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
CVE_DELTA_LOG = f"{CVE_RAW_ROOT}/deltaLog.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_PAGE_TEMPLATES = {
    "avd": "https://avd.aliyun.com/detail?id={id}",
    "cnnvd": "https://www.cnnvd.org.cn/home/globalSearch?keyword={id}",
}
OFFICIAL_HOSTS = {"raw.githubusercontent.com", "services.nvd.nist.gov", "avd.aliyun.com", "www.cnnvd.org.cn", "cnnvd.org.cn"}


def _timestamp(value: str | datetime | None, *, default: datetime | None = None) -> datetime:
    if value is None:
        if default is None:
            raise ValueError("A timestamp is required")
        return default
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {value}") from exc
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


class HttpClient:
    """HTTPS-only client with bounded responses, retries, redirect checks, and rate pacing."""

    def __init__(self, *, allowed_hosts: set[str] | None = None, timeout: int = 30, retries: int = 4,
                 min_interval: float = 0.6, max_bytes: int = 20_000_000,
                 opener: Callable[..., Any] = urlopen, sleeper: Callable[[float], None] = time.sleep) -> None:
        if timeout < 1 or retries < 1 or min_interval < 0 or max_bytes < 1:
            raise ValueError("Invalid HTTP client limits")
        self.allowed_hosts = {host.casefold() for host in (allowed_hosts or OFFICIAL_HOSTS)}
        self.timeout, self.retries = timeout, retries
        self.min_interval, self.max_bytes = min_interval, max_bytes
        self.opener, self.sleeper = opener, sleeper
        self._last_request = 0.0

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.casefold() not in self.allowed_hosts:
            raise ValueError("Collection URL must use HTTPS and an explicitly allowed host")
        if parsed.username or parsed.password:
            raise ValueError("Collection URL cannot contain credentials")

    def request(self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int | None = None) -> Response:
        self._validate_url(url)
        limit = max_bytes or self.max_bytes
        request_headers = {"User-Agent": "VulnToolSuite/0.2 (+local collector)", "Accept": "application/json,text/html;q=0.9"}
        request_headers.update(headers or {})
        for attempt in range(1, self.retries + 1):
            elapsed = time.monotonic() - self._last_request
            if elapsed < self.min_interval:
                self.sleeper(self.min_interval - elapsed)
            self._last_request = time.monotonic()
            try:
                with self.opener(Request(url, headers=request_headers), timeout=self.timeout) as response:
                    final_url = response.geturl()
                    self._validate_url(final_url)
                    body = response.read(limit + 1)
                    if len(body) > limit:
                        raise ValueError(f"Source response exceeds {limit} bytes")
                    return Response(final_url, getattr(response, "status", 200),
                                    {str(key).casefold(): str(value) for key, value in response.headers.items()}, body)
            except HTTPError as exc:
                if exc.code not in {429, 500, 502, 503, 504} or attempt == self.retries:
                    raise
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                delay = min(float(retry_after), 120.0) if retry_after and retry_after.isdigit() else min(2 ** attempt, 30)
                self.sleeper(delay)
            except URLError:
                if attempt == self.retries:
                    raise
                self.sleeper(min(2 ** attempt, 30))
        raise RuntimeError("Unreachable retry state")

    def get_json(self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int | None = None) -> Any:
        response = self.request(url, headers=headers, max_bytes=max_bytes)
        try:
            return json.loads(response.body.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Source did not return valid UTF-8 JSON: {response.url}") from exc

    def get_text(self, url: str, *, headers: dict[str, str] | None = None, max_bytes: int | None = None) -> str:
        response = self.request(url, headers=headers, max_bytes=max_bytes)
        content_type = response.headers.get("content-type", "")
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
        try:
            return response.body.decode(charset)
        except (LookupError, UnicodeDecodeError) as exc:
            raise ValueError(f"Source page has an unsupported character encoding: {response.url}") from exc


def _client_for(url: str, client: Any | None) -> Any:
    if client is not None:
        return client
    return HttpClient(allowed_hosts=OFFICIAL_HOSTS)


def record_url(source: str, identifier: str, url_template: str | None = None) -> str:
    identifier = identifier.strip().upper()
    if source in {"cve", "nvd"} and not CVE_PATTERN.fullmatch(identifier):
        raise ValueError("CVE and NVD collection requires a CVE-YYYY-NNNN identifier")
    if source == "cve":
        _, year, number = identifier.split("-")
        return f"{CVE_RAW_ROOT}/{year}/{number[:-3]}xxx/{identifier}.json"
    if source == "nvd":
        return NVD_API + "?" + urlencode({"cveId": identifier})
    if source not in {"avd", "cnnvd"}:
        raise ValueError(f"Unsupported source: {source}")
    template = url_template or DEFAULT_PAGE_TEMPLATES[source]
    if "{id}" not in template:
        raise ValueError("Page URL template must contain {id}")
    return template.format(id=quote(identifier, safe=""))


def fetch_record(source: str, identifier: str, *, api_key: str | None = None,
                 url_template: str | None = None, client: Any | None = None,
                 authorized_config: str | Path | dict[str, Any] | None = None):
    if authorized_config is not None:
        if source not in {"avd", "cnnvd"}:
            raise ValueError("Authorized API configs only apply to AVD or CNNVD")
        if url_template is not None:
            raise ValueError("Use either authorized_config or url_template, not both")
        from .authorized import fetch_authorized_record, load_authorized_config
        config = load_authorized_config(authorized_config)
        if config["source"] != source:
            raise ValueError("Authorized API config source does not match the requested source")
        return fetch_authorized_record(config, identifier, client=client)
    url = record_url(source, identifier, url_template)
    client = _client_for(url, client)
    headers = {"apiKey": api_key} if source == "nvd" and api_key else None
    if source in {"cve", "nvd"}:
        records = parse(source, client.get_json(url, headers=headers))
        if len(records) != 1 or records[0].vuln_id.casefold() != identifier.casefold():
            raise ValueError("Source response did not contain the requested CVE")
        return records[0]
    html = client.get_text(url, headers={"Accept": "text/html,application/xhtml+xml"})
    return parse_public_page(source, html, url, identifier)


def _merge_report(target: dict[str, int], page: dict[str, int]) -> None:
    for key in ("received", "changed", "unchanged", "stale"):
        target[key] += page[key]


def sync_nvd(store: Store, *, since: str | None = None, until: str | None = None, full: bool = False,
             page_size: int = 2000, max_records: int | None = None, api_key: str | None = None,
             client: Any | None = None, overlap_minutes: int = 5) -> dict[str, Any]:
    if not 1 <= page_size <= 2000:
        raise ValueError("NVD page_size must be between 1 and 2000")
    if max_records is not None and max_records < 1:
        raise ValueError("max_records must be positive")
    client = client or HttpClient(min_interval=.6 if api_key else 6.0)
    stream = "full" if full else "modified"
    state = store.sync_cursor("nvd", stream) or {}
    end = _timestamp(until, default=datetime.now(timezone.utc))
    if full:
        windows: list[tuple[datetime | None, datetime | None]] = [(None, None)]
    else:
        checkpoint = state.get("watermark")
        active_window = state.get("window") if not since else None
        if active_window:
            start = _timestamp(active_window[0])
            active_end = _timestamp(active_window[1])
            if end < active_end:
                raise ValueError("NVD sync end cannot precede the unfinished checkpoint window")
            windows = [(start, active_end)]
            cursor = active_end
        else:
            start_default = _timestamp(checkpoint) - timedelta(minutes=overlap_minutes) if checkpoint else end - timedelta(days=1)
            start = _timestamp(since, default=start_default)
            if start >= end:
                raise ValueError("NVD sync start must be earlier than end")
            windows = []
            cursor = start
        while cursor < end:
            boundary = min(cursor + timedelta(days=120), end)
            windows.append((cursor, boundary))
            cursor = boundary
    report: dict[str, Any] = {"source": "nvd", "stream": stream, "received": 0, "changed": 0,
                              "unchanged": 0, "stale": 0, "pages": 0, "complete": True}
    headers = {"apiKey": api_key} if api_key else None
    remaining = max_records
    for window_number, (window_start, window_end) in enumerate(windows):
        window_key = [_iso(window_start), _iso(window_end)] if window_start else [None, None]
        start_index = state.get("next_start", 0) if state.get("window") == window_key else 0
        while True:
            requested = min(page_size, remaining) if remaining is not None else page_size
            params: dict[str, Any] = {"startIndex": start_index, "resultsPerPage": requested}
            if window_start and window_end:
                params.update({"lastModStartDate": _iso(window_start), "lastModEndDate": _iso(window_end)})
            url = NVD_API + "?" + urlencode(params)
            try:
                payload = client.get_json(url, headers=headers)
            except Exception as exc:
                store.record_collection_failure("nvd", f"page:{window_key[0]}:{start_index}", url, str(exc))
                raise
            rows = payload.get("vulnerabilities")
            if not isinstance(rows, list):
                raise ValueError("NVD response is missing vulnerabilities array")
            records = parse("nvd", payload)
            page_report = store.save_sources_detailed(records)
            _merge_report(report, page_report)
            store.resolve_collection_failure("nvd", f"page:{window_key[0]}:{start_index}")
            report["pages"] += 1
            total = int(payload.get("totalResults", len(rows)))
            response_start = int(payload.get("startIndex", start_index))
            next_start = response_start + len(rows)
            state = {"window": window_key, "next_start": next_start, "watermark": state.get("watermark")}
            store.save_sync_cursor("nvd", state, stream)
            if remaining is not None:
                remaining -= len(rows)
                if remaining <= 0 and next_start < total:
                    report["complete"] = False
                    report["next_start"] = next_start
                    return report
            if next_start >= total:
                break
            if not rows:
                raise ValueError("NVD pagination stopped before totalResults was reached")
            start_index = next_start
        watermark_time = window_end or end
        if state.get("watermark"):
            watermark_time = max(watermark_time, _timestamp(state["watermark"]))
        watermark = _iso(watermark_time)
        state = {"window": None, "next_start": 0, "watermark": watermark, "complete": True}
        store.save_sync_cursor("nvd", state, stream)
        if remaining is not None and remaining <= 0 and window_number < len(windows) - 1:
            report["complete"] = False
            report["watermark"] = watermark
            return report
    report["watermark"] = state.get("watermark")
    return report


def sync_cve_delta(store: Store, *, since: str | None = None, max_records: int | None = None,
                   client: Any | None = None, overlap_minutes: int = 5) -> dict[str, Any]:
    if max_records is not None and max_records < 1:
        raise ValueError("max_records must be positive")
    client = client or HttpClient(min_interval=.6, max_bytes=80_000_000)
    events = client.get_json(CVE_DELTA_LOG, max_bytes=80_000_000)
    if not isinstance(events, list) or not events:
        raise ValueError("CVE deltaLog.json is empty or has an unexpected shape")
    ordered_events = sorted(events, key=lambda item: _timestamp(item["fetchTime"]))
    state = store.sync_cursor("cve", "delta") or {}
    explicit_start = since or state.get("scan_start") or state.get("watermark")
    latest = _timestamp(ordered_events[-1]["fetchTime"])
    checkpoint_time = _timestamp(explicit_start, default=latest - timedelta(days=1))
    oldest = _timestamp(ordered_events[0]["fetchTime"])
    if explicit_start and checkpoint_time < oldest:
        raise ValueError("CVE checkpoint predates the rolling delta log; import an official baseline before resuming")
    start = checkpoint_time - timedelta(minutes=overlap_minutes)
    selected = [event for event in ordered_events if _timestamp(event["fetchTime"]) > start]
    discovered: dict[str, dict[str, Any]] = {}
    for event in selected:
        for item in [*event.get("new", []), *event.get("updated", [])]:
            cve_id = str(item.get("cveId", "")).upper()
            if CVE_PATTERN.fullmatch(cve_id):
                candidate = {**item, "_fetchTime": event["fetchTime"]}
                previous = discovered.get(cve_id)
                if previous is None or (candidate["_fetchTime"], str(candidate.get("dateUpdated", ""))) > (
                        previous["_fetchTime"], str(previous.get("dateUpdated", ""))):
                    discovered[cve_id] = candidate
    items = sorted(discovered.values(), key=lambda item: (item["_fetchTime"], item["cveId"]))
    resume_after = tuple(state.get("next_after", [])) if not since else ()
    if resume_after:
        items = [item for item in items if (item["_fetchTime"], item["cveId"]) > resume_after]
    truncated = max_records is not None and len(items) > max_records
    if max_records is not None:
        items = items[:max_records]
    report: dict[str, Any] = {"source": "cve", "stream": "delta", "discovered": len(discovered),
                              "received": 0, "changed": 0, "unchanged": 0, "stale": 0,
                              "failed": 0, "complete": not truncated}
    for item in items:
        cve_id = item["cveId"].upper()
        url = item.get("githubLink") or record_url("cve", cve_id)
        expected = record_url("cve", cve_id)
        if url != expected:
            error = "CVE delta record URL did not match the official repository path"
            store.record_collection_failure("cve", cve_id, url, error)
            report["failed"] += 1
            continue
        try:
            record = fetch_record("cve", cve_id, client=client)
            _merge_report(report, store.save_sources_detailed([record]))
            store.resolve_collection_failure("cve", cve_id)
        except Exception as exc:
            store.record_collection_failure("cve", cve_id, url, str(exc))
            report["failed"] += 1
    if not truncated and report["failed"] == 0:
        watermark = _iso(latest)
        store.save_sync_cursor("cve", {"watermark": watermark, "complete": True}, "delta")
        report["watermark"] = watermark
    elif truncated and report["failed"] == 0 and items:
        last = items[-1]
        next_after = [last["_fetchTime"], last["cveId"]]
        store.save_sync_cursor("cve", {"scan_start": _iso(checkpoint_time), "next_after": next_after,
                                       "complete": False}, "delta")
        report["next_after"] = next_after
    return report


def sync_cve_directory(store: Store, directory: str | Path, *, batch_size: int = 500,
                       max_records: int | None = None) -> dict[str, Any]:
    """Resume a baseline import from an official cvelistV5 checkout or extracted release."""
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError("CVE baseline directory does not exist")
    if not 1 <= batch_size <= 5000:
        raise ValueError("CVE baseline batch_size must be between 1 and 5000")
    if max_records is not None and max_records < 1:
        raise ValueError("max_records must be positive")
    files = sorted(item for item in root.rglob("*.json") if item.name not in {"delta.json", "deltaLog.json"})
    state = store.sync_cursor("cve", "baseline") or {}
    resume_after = state.get("next_after") if not state.get("complete") else None
    report: dict[str, Any] = {"source": "cve", "stream": "baseline", "discovered": len(files),
                              "received": 0, "changed": 0, "unchanged": 0, "stale": 0,
                              "failed": 0, "complete": True}
    batch = []
    last_relative = None
    processed = 0
    encountered_failure = False
    for path in files:
        relative = path.relative_to(root).as_posix()
        if resume_after and relative <= resume_after:
            continue
        if max_records is not None and processed >= max_records:
            report["complete"] = False
            break
        failure_id = f"file:{relative}"
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
            records = parse("cve", payload)
            if len(records) != 1:
                raise ValueError("CVE baseline file must contain exactly one record")
            batch.append(records[0])
            store.resolve_collection_failure("cve", failure_id)
        except Exception as exc:
            store.record_collection_failure("cve", failure_id, path.as_uri(), str(exc))
            report["failed"] += 1
            encountered_failure = True
        processed += 1
        last_relative = relative
        if len(batch) >= batch_size:
            _merge_report(report, store.save_sources_detailed(batch))
            batch = []
            if not encountered_failure:
                store.save_sync_cursor("cve", {"next_after": relative, "complete": False}, "baseline")
    if batch:
        _merge_report(report, store.save_sources_detailed(batch))
    if report["complete"] and report["failed"] == 0:
        store.save_sync_cursor("cve", {"next_after": None, "complete": True,
                                       "completed_at": _iso(datetime.now(timezone.utc))}, "baseline")
    elif report["failed"]:
        report["complete"] = False
        store.save_sync_cursor("cve", {"next_after": resume_after, "complete": False}, "baseline")
        report["next_after"] = resume_after
    elif last_relative:
        store.save_sync_cursor("cve", {"next_after": last_relative, "complete": False}, "baseline")
        report["next_after"] = last_relative
    return report


def collect_batch(store: Store, source: str, identifiers: list[str], *, api_key: str | None = None,
                  url_template: str | None = None, client: Any | None = None,
                  authorized_config: str | Path | dict[str, Any] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {"source": source, "requested": len(identifiers), "received": 0,
                              "changed": 0, "unchanged": 0, "stale": 0, "failed": 0, "failures": []}
    for identifier in identifiers:
        identifier = identifier.strip().upper()
        if not identifier:
            continue
        url = None
        try:
            if authorized_config is not None:
                from .authorized import load_authorized_config, request_parts
                config = load_authorized_config(authorized_config)
                url = request_parts(config, identifier)[0]
            else:
                url = record_url(source, identifier, url_template)
            record = fetch_record(source, identifier, api_key=api_key, url_template=url_template, client=client,
                                  authorized_config=authorized_config)
            _merge_report(report, store.save_sources_detailed([record]))
            store.resolve_collection_failure(source, identifier)
        except Exception as exc:
            store.record_collection_failure(source, identifier, url, str(exc))
            report["failed"] += 1
            report["failures"].append({"id": identifier, "error": str(exc)})
    return report


def collection_status(store: Store) -> dict[str, Any]:
    cursors = [{"source": row[0], "stream": row[1], "cursor": json.loads(row[2]), "updated_at": row[3]}
               for row in store.db.execute("SELECT source,stream,cursor,updated_at FROM sync_state ORDER BY source,stream")]
    return {"source_records": {row[0]: row[1] for row in store.db.execute(
                "SELECT source,count(*) FROM source_latest GROUP BY source ORDER BY source")},
            "history_records": store.db.execute("SELECT count(*) FROM source_history").fetchone()[0],
            "cursors": cursors, "unresolved_failures": store.collection_failures()}
