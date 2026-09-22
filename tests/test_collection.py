import json
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

import pytest

from vulntools.authorized import fetch_authorized_record, load_authorized_config
from vulntools.collection import (CVE_DELTA_LOG, HttpClient, collect_batch, collection_status,
                                  fetch_record, record_url, sync_cve_delta, sync_nvd)
from vulntools.collection import sync_cve_directory
from vulntools.collectors import parse, parse_public_page, read_file
from vulntools.models import SourceRecord
from vulntools.storage import Store


def nvd_item(cve_id, modified="2026-01-01T12:00:00.000Z"):
    return {"cve": {"id": cve_id, "vulnStatus": "Analyzed", "lastModified": modified,
                    "published": "2026-01-01T00:00:00.000Z",
                    "descriptions": [{"lang": "en", "value": f"Description for {cve_id}"}],
                    "weaknesses": [], "metrics": {}, "references": []}}


def cve_item(cve_id, modified="2026-01-01T12:00:00.000Z"):
    return {"dataType": "CVE_RECORD", "dataVersion": "5.2", "cveMetadata": {
                "cveId": cve_id, "state": "PUBLISHED", "dateUpdated": modified,
                "datePublished": "2026-01-01T00:00:00.000Z"},
            "containers": {"cna": {"title": cve_id, "descriptions": [{"lang": "en", "value": "example"}],
                                    "affected": [], "problemTypes": [], "references": []}}}


class FakeClient:
    def __init__(self, json_handler=None, text_handler=None):
        self.json_handler = json_handler
        self.text_handler = text_handler
        self.calls = []

    def get_json(self, url, **kwargs):
        self.calls.append(url)
        if callable(self.json_handler):
            return self.json_handler(url)
        if url not in self.json_handler:
            raise RuntimeError("missing fixture")
        value = self.json_handler[url]
        if isinstance(value, Exception):
            raise value
        return value

    def get_text(self, url, **kwargs):
        self.calls.append(url)
        if callable(self.text_handler):
            return self.text_handler(url)
        if url not in self.text_handler:
            raise RuntimeError("missing fixture")
        value = self.text_handler[url]
        if isinstance(value, Exception):
            raise value
        return value


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "collection.sqlite") as result:
        yield result


def test_nvd_pagination_checkpoint_and_full_resume(store):
    rows = [nvd_item(f"CVE-2026-{number}") for number in range(1000, 1003)]

    def respond(url):
        params = parse_qs(urlparse(url).query)
        start = int(params["startIndex"][0])
        size = int(params["resultsPerPage"][0])
        return {"startIndex": start, "resultsPerPage": size, "totalResults": len(rows),
                "vulnerabilities": rows[start:start + size]}

    client = FakeClient(json_handler=respond)
    partial = sync_nvd(store, full=True, page_size=2, max_records=1, client=client)
    assert partial["complete"] is False and partial["received"] == 1
    assert store.sync_cursor("nvd", "full")["next_start"] == 1
    resumed = sync_nvd(store, full=True, page_size=2, client=client)
    assert resumed["complete"] is True and resumed["received"] == 2
    assert len(store.sources()) == 3
    assert "startIndex=1" in client.calls[1]


def test_authorized_api_uses_environment_secret_and_strict_mapping():
    config = {
        "schema": "vulntools/authorized-api/v1", "source": "avd",
        "endpoint_template": "https://licensed.example.test/v1/vulns/{id}",
        "response_format": "mapped-json/v1", "record_pointer": "/data",
        "auth": {"token_env": "AVD_TEST_TOKEN", "header": "X-Api-Key", "scheme": ""},
        "mapping": {
            "source_id": "/id", "url": "/permalink", "aliases": "/aliases",
            "source_updated_at": "/updated", "fields": {
                "title": "/title", "description": "/description", "components": "/affected"
            },
        },
    }

    class AuthorizedClient:
        def __init__(self):
            self.headers = None

        def get_json(self, url, headers=None):
            assert url.endswith("/AVD-2026-1000")
            self.headers = headers
            return {"data": {
                "id": "AVD-2026-1000", "permalink": "https://licensed.example.test/v/1000",
                "aliases": ["CVE-2026-1000"], "updated": "2026-09-15T00:00:00Z",
                "title": "Authorized record", "description": "Evidence from licensed API",
                "affected": [{"vendor": "Example", "name": "Widget", "versions": []}],
            }}

    client = AuthorizedClient()
    record = fetch_authorized_record(config, "AVD-2026-1000", client=client,
                                     environ={"AVD_TEST_TOKEN": "secret-value"})
    assert client.headers["X-Api-Key"] == "secret-value"
    assert record.vuln_id == "CVE-2026-1000"
    assert record.fields["title"] == "Authorized record"
    assert "secret-value" not in json.dumps(record.to_dict())


def test_authorized_api_config_rejects_embedded_credentials():
    config = {
        "schema": "vulntools/authorized-api/v1", "source": "cnnvd",
        "endpoint_template": "https://licensed.example.test/{id}",
        "auth": {"token": "must-not-be-here"},
    }
    with pytest.raises(ValueError, match="Credentials cannot be stored"):
        load_authorized_config(config)


def test_nvd_modified_window_and_stale_source_rejection(store):
    def respond(url):
        params = parse_qs(urlparse(url).query)
        assert "lastModStartDate" in params and "lastModEndDate" in params
        return {"startIndex": 0, "resultsPerPage": 10, "totalResults": 1,
                "vulnerabilities": [nvd_item("CVE-2026-1100", "2026-01-02T00:00:00Z")]}

    report = sync_nvd(store, since="2026-01-01T00:00:00Z", until="2026-01-02T00:00:00Z",
                      page_size=10, client=FakeClient(json_handler=respond))
    assert report["watermark"] == "2026-01-02T00:00:00.000Z"
    older = SourceRecord("nvd", "CVE-2026-1100", "https://example.invalid", {},
                         fields={"description": "old"}, source_updated_at="2026-01-01T00:00:00Z")
    saved = store.save_sources_detailed([older])
    assert saved["stale"] == 1
    assert store.sources()[0].fields["description"] != "old"


def test_nvd_modified_page_resume_and_long_window_split(store):
    rows = [nvd_item(f"CVE-2026-{number}") for number in range(1150, 1153)]

    def respond(url):
        params = parse_qs(urlparse(url).query)
        start = int(params["startIndex"][0])
        size = int(params["resultsPerPage"][0])
        return {"startIndex": start, "resultsPerPage": size, "totalResults": len(rows),
                "vulnerabilities": rows[start:start + size]}

    client = FakeClient(json_handler=respond)
    partial = sync_nvd(store, since="2026-01-01T00:00:00Z", until="2026-01-02T00:00:00Z",
                       page_size=2, max_records=1, client=client)
    assert partial["complete"] is False
    resumed = sync_nvd(store, until="2026-01-02T00:00:00Z", page_size=2, client=client)
    assert resumed["complete"] is True and resumed["received"] == 2
    assert "startIndex=1" in client.calls[1]

    empty = FakeClient(json_handler=lambda url: {"startIndex": 0, "resultsPerPage": 10,
                                                  "totalResults": 0, "vulnerabilities": []})
    report = sync_nvd(store, since="2025-01-01T00:00:00Z", until="2025-09-01T00:00:00Z",
                      page_size=10, client=empty)
    assert report["pages"] == 3
    assert store.sync_cursor("nvd", "modified")["watermark"] == "2026-01-02T00:00:00.000Z"


def test_cve_delta_deduplicates_and_advances_only_after_success(store):
    first, second = "CVE-2026-1200", "CVE-2026-1201"
    events = [
        {"fetchTime": "2025-12-31T23:50:00Z", "numberOfChanges": 0, "new": [], "updated": [], "error": []},
        {"fetchTime": "2026-01-01T01:10:00Z", "numberOfChanges": 2,
         "new": [{"cveId": first, "githubLink": record_url("cve", first), "dateUpdated": "2026-01-01T01:01:00Z"}],
         "updated": [{"cveId": first, "githubLink": record_url("cve", first), "dateUpdated": "2026-01-01T01:05:00Z"}], "error": []},
        {"fetchTime": "2026-01-01T01:20:00Z", "numberOfChanges": 1,
         "new": [{"cveId": second, "githubLink": record_url("cve", second), "dateUpdated": "2026-01-01T01:15:00Z"}],
         "updated": [], "error": []},
    ]
    fixture = {CVE_DELTA_LOG: events, record_url("cve", first): cve_item(first),
               record_url("cve", second): cve_item(second)}
    client = FakeClient(json_handler=fixture)
    partial = sync_cve_delta(store, since="2026-01-01T01:00:00Z", max_records=1, client=client)
    assert partial["discovered"] == 2 and partial["received"] == 1 and partial["complete"] is False
    assert store.sync_cursor("cve", "delta")["next_after"][1] == first
    report = sync_cve_delta(store, client=client)
    assert report["received"] == 1 and report["failed"] == 0 and report["complete"] is True
    assert store.sync_cursor("cve", "delta")["watermark"] == "2026-01-01T01:20:00.000Z"


def test_public_page_parsing_and_waf_detection():
    html = """<html><head><title>Example detail</title><meta name="description" content="fallback"></head><body>
      <h1>Example Product 路径遍历漏洞</h1><p>AVD-2026-1300 CVE-2026-1300 CWE-22</p>
      <dl><dt>漏洞描述</dt><dd>处理不可信压缩包时未校验目标路径。</dd>
      <dt>危害等级</dt><dd>高危</dd><dt>影响产品</dt><dd>Example Product 1.x</dd>
      <dt>更新时间</dt><dd>2026-01-03 12:30:00</dd></dl>
      <a href="https://vendor.example/advisory">参考链接</a></body></html>"""
    record = parse_public_page("avd", html, "https://avd.aliyun.com/detail?id=AVD-2026-1300", "AVD-2026-1300")
    assert record.source_id == "AVD-2026-1300"
    assert record.aliases == ["AVD-2026-1300", "CVE-2026-1300"]
    assert record.fields["severity"] == "high"
    assert record.fields["weaknesses"] == ["CWE-22"]
    assert record.fields["components"][0]["name"] == "Example Product 1.x"
    assert record.source_updated_at.endswith("+08:00")
    with pytest.raises(ValueError, match="WAF"):
        parse_public_page("avd", '{"_waf_token":"challenge"}', "https://avd.aliyun.com/detail?id=x")


def test_cve_program_and_adp_containers_are_preserved():
    payload = cve_item("CVE-2026-1350")
    payload["containers"]["adp"] = [{
        "title": "CVE Program Container",
        "affected": [{"vendor": "Example", "product": "Widget", "packageURL": "pkg:pypi/widget",
                      "defaultStatus": "unaffected", "versions": [{"version": "1", "status": "affected"}]}],
        "references": [{"url": "https://example.invalid/program-reference"}],
        "metrics": [{"other": {"type": "ssvc", "content": {"version": "2.0.3"}}}],
    }]
    record = parse("cve", payload)[0]
    assert record.source_updated_at == "2026-01-01T12:00:00.000Z"
    assert record.fields["components"][0]["packageURL"] == "pkg:pypi/widget"
    assert record.fields["ssvc"]["version"] == "2.0.3"
    assert "https://example.invalid/program-reference" in record.references


def test_nvd_affected_extension_is_projected():
    payload = nvd_item("CVE-2026-1351")
    payload["cve"]["affected"] = [{"vendor": "Example", "product": "Widget", "packageURL": "pkg:npm/widget",
                                    "versions": [{"version": "0", "lessThan": "2", "status": "affected"}]}]
    record = parse("nvd", payload)[0]
    assert record.fields["components"][0]["name"] == "Widget"
    assert record.fields["components"][0]["packageURL"] == "pkg:npm/widget"


def test_batch_continues_records_failure_and_later_resolves(store):
    good, bad = "CVE-2026-1400", "CVE-2026-1401"

    def first_response(url):
        if bad in url:
            raise RuntimeError("temporary outage")
        return cve_item(good)

    report = collect_batch(store, "cve", [good, bad], client=FakeClient(json_handler=first_response))
    assert report["changed"] == 1 and report["failed"] == 1
    assert collection_status(store)["unresolved_failures"][0]["item_id"] == bad

    def recovered(url):
        return cve_item(bad)

    retried = collect_batch(store, "cve", [bad], client=FakeClient(json_handler=recovered))
    assert retried["changed"] == 1 and collection_status(store)["unresolved_failures"] == []


def test_directory_import_skips_delta_metadata(tmp_path):
    root = tmp_path / "cves"
    root.mkdir()
    (root / "CVE-2026-1500.json").write_text(json.dumps(cve_item("CVE-2026-1500")), encoding="utf-8")
    (root / "delta.json").write_text(json.dumps({"new": []}), encoding="utf-8")
    assert [item.vuln_id for item in read_file("cve", root)] == ["CVE-2026-1500"]


def test_cve_baseline_directory_resumes_by_file(store, tmp_path):
    root = tmp_path / "official-cves"
    root.mkdir()
    for number in range(1500, 1503):
        (root / f"CVE-2026-{number}.json").write_text(json.dumps(cve_item(f"CVE-2026-{number}")), encoding="utf-8")
    first = sync_cve_directory(store, root, batch_size=1, max_records=1)
    assert first["complete"] is False and first["received"] == 1
    assert store.sync_cursor("cve", "baseline")["next_after"] == "CVE-2026-1500.json"
    second = sync_cve_directory(store, root, batch_size=1)
    assert second["complete"] is True and second["received"] == 2
    assert len(store.sources()) == 3


def test_cve_baseline_failure_does_not_advance_past_bad_file(store, tmp_path):
    root = tmp_path / "official-cves-with-error"
    root.mkdir()
    (root / "CVE-2026-1510.json").write_text("not json", encoding="utf-8")
    (root / "CVE-2026-1511.json").write_text(json.dumps(cve_item("CVE-2026-1511")), encoding="utf-8")
    result = sync_cve_directory(store, root, batch_size=1)
    assert result["complete"] is False and result["failed"] == 1
    assert store.sync_cursor("cve", "baseline")["next_after"] is None
    assert collection_status(store)["unresolved_failures"][0]["item_id"].startswith("file:")


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json; charset=utf-8"}

    def __init__(self, url, body):
        self.url, self.body = url, body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def geturl(self):
        return self.url

    def read(self, size):
        return self.body[:size]


def test_http_client_retries_and_rejects_unapproved_hosts():
    url = "https://services.nvd.nist.gov/test"
    attempts, delays = [], []

    def opener(request, timeout):
        attempts.append(request.full_url)
        if len(attempts) == 1:
            raise HTTPError(url, 429, "rate", {"Retry-After": "0"}, None)
        return FakeResponse(url, b'{"ok":true}')

    client = HttpClient(allowed_hosts={"services.nvd.nist.gov"}, retries=2, min_interval=0,
                        opener=opener, sleeper=delays.append)
    assert client.get_json(url) == {"ok": True}
    assert len(attempts) == 2 and delays == [0.0]
    with pytest.raises(ValueError, match="allowed host"):
        client.get_json("https://example.invalid/private")
