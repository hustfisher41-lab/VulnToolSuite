from dataclasses import replace
import json
import math
import socket

import pytest
import vulntools.search as search_module

from vulntools.analytics import quality_report, read_training_log
from vulntools.cli import main
from vulntools.collectors import parse, read_file
from vulntools.demo import demo_sources
from vulntools.embedding import HashEncoder, index_records
from vulntools.models import SourceRecord
from vulntools.processing import enrichment_plan, process, static_python_features
from vulntools.sandbox import SandboxPolicy, analyze_events, execute_sample, preflight
from vulntools.search import cpe_applicability, evaluate, index_status, record_similarity, search, version_match
from vulntools.storage import Store


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline tests must not access the network")
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def store(tmp_path):
    with Store(tmp_path / "test.sqlite") as database:
        yield database


def seed(store):
    store.save_sources(demo_sources())
    store.replace_canonical(process(store.sources()))
    index_records(store, HashEncoder())


def test_four_sources_merge_and_preserve_conflicts():
    sources = demo_sources()
    assert {r.source for r in sources} == {"cve", "nvd", "avd", "cnnvd"}
    records = process(sources)
    assert len(records) == 3
    record = records[0]
    assert record["fields"]["severity"] == "high"
    assert record["field_states"]["severity"] == "conflicted"
    assert len(record["conflicts"]["severity"]) == 2
    assert record["fields"]["patch"]
    assert record["fields"]["poc"] is None
    assert record["field_states"]["poc"] == "missing"
    assert all(x["url"] and x["raw_hash"] for x in record["provenance"]["severity"])


def test_source_import_idempotence_and_revision_history(store):
    source = demo_sources()[0]
    assert store.save_sources([source]) == 1
    assert store.save_sources([replace(source, fetched_at="2099-12-12")]) == 0
    changed = replace(source, fields={**source.fields, "title": "Revised"}, raw={**source.raw, "revision": 2})
    assert store.save_sources([changed]) == 1
    assert store.db.execute("SELECT count(*) FROM source_history").fetchone()[0] == 2
    assert store.sources()[0].fields["title"] == "Revised"


def test_raw_reversion_restores_latest(store):
    original = demo_sources()[0]
    store.save_sources([original])
    store.save_sources([replace(original, fields={**original.fields, "title": "Changed"})])
    assert store.save_sources([original]) == 1
    assert store.sources()[0].fields["title"] == original.fields["title"]


def test_revision_stable_across_order_and_timestamp():
    sources = demo_sources()
    first = process(sources)
    second = process([replace(x, fetched_at="later") for x in reversed(sources)])
    assert first == second


def test_shared_reference_does_not_merge_different_vulnerabilities():
    sources = [SourceRecord("avd", "A-1", "https://example.invalid/shared", {}, fields={"description": "same"}),
               SourceRecord("avd", "A-2", "https://example.invalid/shared", {}, fields={"description": "same"})]
    assert len(process(sources)) == 2


def test_ambiguous_cve_identity_is_rejected():
    with pytest.raises(ValueError, match="multiple CVE"):
        SourceRecord("avd", "A-1", "https://example.invalid", {}, aliases=["CVE-2099-1001", "CVE-2099-1002"])


def test_missing_plan_has_no_invented_values():
    records = process(demo_sources())
    plan = enrichment_plan(records)
    assert plan[0]["status"] == "awaiting_search_provider"
    assert "poc" in plan[0]["missing_fields"]
    assert records[0]["fields"]["poc"] is None


def test_index_and_search_chinese_and_english(store):
    seed(store)
    for query in ("解压路径穿越", "archive destination path"):
        hits = search(store, HashEncoder(), query, top_k=2)
        assert hits[0]["vuln_id"] == "CVE-2099-1001"
        assert hits[0]["source_urls"] and hits[0]["evidence"]
        assert hits[0]["semantic_model"] is False
        assert set(hits[0]["scores"]) == {"cosine", "bm25", "rrf"}
        assert hits[0]["rank"] == 1
        assert hits[0]["score_breakdown"]["query"]["best_view"]


def test_large_index_uses_bounded_two_stage_ranking(store, monkeypatch):
    seed(store)
    monkeypatch.setattr(search_module, "SCALABLE_SCAN_THRESHOLD", 1)
    hits = search(store, HashEncoder(), "archive destination path", top_k=2)
    assert hits[0]["vuln_id"] == "CVE-2099-1001"
    assert hits[0]["index_backend"] == "sqlite_two_stage"


def test_index_batches_documents_and_search_uses_query_encoder(store):
    store.save_sources(demo_sources())
    store.replace_canonical(process(store.sources()))

    class TrackingEncoder(HashEncoder):
        def __init__(self):
            super().__init__()
            self.document_batches = []
            self.query_texts = []
            self.manifest = {**self.manifest, "provider": "tracking-test"}

        def encode_documents(self, texts):
            self.document_batches.append(list(texts))
            return [super(TrackingEncoder, self).encode(text) for text in texts]

        def encode_query(self, text):
            self.query_texts.append(text)
            return super().encode(text)

    encoder = TrackingEncoder()
    report = index_records(store, encoder, batch_size=4)
    assert report["complete"] is True
    assert report["remaining_records"] == 0
    assert len(encoder.document_batches) < report["indexed_views"]
    assert encoder.query_texts == []
    assert search(store, encoder, "archive destination path")
    assert encoder.query_texts == ["archive destination path"]


def test_partial_semantic_index_can_resume(store):
    store.save_sources(demo_sources())
    store.replace_canonical(process(store.sources()))
    encoder = HashEncoder(256)
    first = index_records(store, encoder, max_records=1)
    second = index_records(store, encoder, max_records=1)
    final = index_records(store, encoder, max_records=1)
    assert [first["remaining_records"], second["remaining_records"], final["remaining_records"]] == [2, 1, 0]
    assert final["complete"] is True


def test_explicit_cve_identifier_is_ranked_first(store):
    seed(store)
    hits = search(store, HashEncoder(), "CVE-2099-1001 generic vulnerability", top_k=3)
    assert hits[0]["vuln_id"] == "CVE-2099-1001"


def test_multiview_index_status_and_similarity(store):
    seed(store)
    status = index_status(store, HashEncoder())
    assert status["ready"] is True
    assert status["indexed_records"] == status["active_records"] == 3
    assert status["views"]["aggregate"] == 3
    assert status["views"]["description"] == 3
    assert status["views"]["component"] == 1
    result = record_similarity(store, HashEncoder(), "CVE-2099-1001", "CVE-2099-1001",
                               ["aggregate", "description"])
    assert result["aggregate_similarity"] == pytest.approx(1)
    assert result["compared_views"] == ["aggregate", "description"]


def test_poc_view_retrieval_modes_and_additional_filters(store):
    records = [
        SourceRecord("avd", "A-POC", "https://example.invalid/poc", {}, aliases=["CVE-2099-2001"],
                     fields={"description": "A service input validation flaw.", "poc": "requests.get(url + '/export?path=../../etc/passwd')",
                             "weaknesses": ["CWE-22"]}),
        SourceRecord("cnnvd", "B-POC", "https://example.invalid/sql", {}, aliases=["CVE-2099-2002"],
                     fields={"description": "A database query vulnerability.", "poc": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
                             "weaknesses": ["CWE-89"]}),
    ]
    store.save_sources(records)
    store.replace_canonical(process(store.sources()))
    report = index_records(store, HashEncoder())
    assert report["view_schema"] == "multiview/v1"
    for mode in ("hybrid", "dense", "sparse"):
        hit = search(store, HashEncoder(), poc="SELECT users cursor.execute", weakness="CWE-89",
                     source="cnnvd", mode=mode)[0]
        assert hit["vuln_id"] == "CVE-2099-2002"
        assert hit["score_breakdown"]["poc"]["best_view"] == "poc"
        assert hit["retrieval_mode"] == mode
    assert search(store, HashEncoder(), "database", weakness="CWE-22", source="cnnvd") == []


def test_retrieval_evaluation_is_reproducible(store):
    seed(store)
    report = evaluate(store, HashEncoder(), [
        {"id": "path", "query": "archive destination path", "relevant": ["CVE-2099-1001"]},
        {"id": "xss", "query": "unescaped HTML cross site scripting", "relevant": ["CVE-2099-1002"]},
    ], [1, 2])
    assert report["recall"] == {"@1": 1.0, "@2": 1.0}
    assert report["mrr"] == 1.0
    assert report["ndcg"]["@2"] == 1.0
    assert 0 <= report["latency_ms"]["min"] <= report["latency_ms"]["p95"]


def test_strict_filters_never_fall_back(store):
    seed(store)
    assert search(store, HashEncoder(), "archive", severity="critical") == []
    assert search(store, HashEncoder(), "archive", component="not-a-component") == []
    assert search(store, HashEncoder(), "archive", component="demo-archive", version="1.2.0") == []
    assert search(store, HashEncoder(), "archive", component="demo-archive", version="1.1.9")[0]["version_match"] == "affected"


@pytest.mark.parametrize("version,expected", [("1.0.0", "affected"), ("1.1.0", "affected"), ("1.2.0", "unaffected"), ("0.9.0", "unaffected"), ("1.1.0-rc1", "affected")])
def test_version_boundaries(version, expected):
    component = demo_sources()[0].fields["components"][0]
    assert version_match(component, version) == expected


def test_unknown_version_scheme_is_not_guessed():
    component = {"versions": [{"version": "1.0", "lessThan": "2.0", "versionType": "vendor-custom", "status": "affected"}], "default_status": "unaffected"}
    assert version_match(component, "1.5") == "unknown"


def test_ecosystem_versions_and_status_changes():
    python_component = {
        "name": "widget", "packageURL": "pkg:pypi/widget",
        "versions": [{"version": "1.0rc1", "lessThan": "2.0", "status": "affected"}],
        "default_status": "unaffected",
    }
    assert version_match(python_component, "1.0") == "affected"
    assert version_match(python_component, "2.0") == "unaffected"
    changed = {
        "name": "widget", "packageURL": "pkg:npm/widget",
        "versions": [{"version": "1.0.0", "lessThan": "3.0.0", "versionType": "semver",
                      "status": "affected", "changes": [{"at": "2.0.0", "status": "unaffected"}]}],
        "default_status": "unaffected",
    }
    assert version_match(changed, "1.9.0") == "affected"
    assert version_match(changed, "2.1.0") == "unaffected"


def test_nvd_cpe_boolean_applicability_requires_complete_context():
    configurations = [{"nodes": [{
        "operator": "AND", "negate": False, "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"},
            {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"},
        ],
    }]}]
    affected = ["cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*",
                "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*"]
    wrong_os = ["cpe:2.3:a:acme:widget:1.5:*:*:*:*:*:*:*",
                "cpe:2.3:o:linux:linux_kernel:6.0:*:*:*:*:*:*:*"]
    assert cpe_applicability(configurations, affected) == "affected"
    assert cpe_applicability(configurations, wrong_os) == "unaffected"
    assert cpe_applicability(configurations, affected[:1]) == "unaffected"
    environment_only = [{"nodes": [{"operator": "OR", "cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"}
    ]}]}]
    assert cpe_applicability(environment_only, affected) == "unknown"
    excluded_environment = [{"operator": "AND", "children": [
        {"operator": "OR", "cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}
        ]},
        {"operator": "OR", "negate": True, "cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows_xp:*:*:*:*:*:*:*:*"}
        ]},
    ]}]
    assert cpe_applicability(excluded_environment, affected) == "affected"
    xp = [affected[0], "cpe:2.3:o:microsoft:windows_xp:sp3:*:*:*:*:*:*:*"]
    assert cpe_applicability(excluded_environment, xp) == "unaffected"


def test_index_upsert_and_revision_invalidation(store):
    seed(store)
    assert index_records(store, HashEncoder())["skipped"] == 3
    record = demo_sources()[0]
    store.save_sources([replace(record, fields={**record.fields, "description": "A revised description"})])
    store.replace_canonical(process(store.sources()))
    assert store.db.execute("SELECT count(*) FROM vectors").fetchone()[0] == 2
    result = index_records(store, HashEncoder())
    assert result["indexed"] == 1 and result["skipped"] == 2
    assert store.db.execute("SELECT count(*) FROM canonical_history").fetchone()[0] == 4


def test_official_rejection_removes_search_hit(store):
    seed(store)
    store.save_sources([replace(demo_sources()[0], status="rejected")])
    store.replace_canonical(process(store.sources()))
    index_records(store, HashEncoder())
    assert all(x["vuln_id"] != "CVE-2099-1001" for x in search(store, HashEncoder(), "archive"))


def test_wrong_model_index_is_rejected(store):
    seed(store)
    with pytest.raises(ValueError, match="compatible index"):
        search(store, HashEncoder(256), "archive")


def test_embedding_failure_rolls_back_entire_index(store):
    store.save_sources(demo_sources())
    store.replace_canonical(process(store.sources()))
    class Broken(HashEncoder):
        def encode(self, text):
            return [math.nan] * 512
    with pytest.raises(ValueError, match="non-finite"):
        index_records(store, Broken())
    assert store.db.execute("SELECT count(*) FROM vectors").fetchone()[0] == 0
    assert store.db.execute("SELECT count(*) FROM vector_views").fetchone()[0] == 0
    assert store.db.execute("SELECT count(*) FROM vector_models").fetchone()[0] == 0


def test_static_code_is_not_executed(tmp_path):
    marker = tmp_path / "must-not-exist"
    code = f"from pathlib import Path\nPath({str(marker)!r}).touch()"
    features = static_python_features(code)
    assert "Path" in features["calls"]
    assert not marker.exists()
    assert static_python_features("def broken:")["parse_error"]


def test_quality_report_empty_and_missing():
    assert quality_report([])["coverage"]["poc"] is None
    report = quality_report(process(demo_sources()))
    assert report["missing_fields"]["poc"] == 3
    assert report["conflicted_fields"]["severity"] == 1


def test_training_nan_and_out_of_order_are_flagged(tmp_path):
    file = tmp_path / "train.jsonl"
    file.write_text('{"step":2,"loss":NaN}\n{"step":1,"loss":2.0}\n', encoding="utf-8")
    rows, errors = read_training_log(file)
    assert rows[0]["loss"] is None
    assert {x["kind"] for x in errors} == {"invalid_metric", "non_increasing_step"}


@pytest.mark.parametrize("changes", [{"network": "public"}, {"host_mounts": True}, {"isolation": "container"}, {"timeout_seconds": 0}, {"external_watchdog": False}, {"host_mounts": "false"}, {"memory_mb": True}])
def test_sandbox_rejects_unsafe_or_mistyped_policy(changes):
    assert not preflight(SandboxPolicy(**changes))["policy_valid"]


def test_sandbox_never_claims_execution_ready():
    assert preflight(SandboxPolicy())["policy_valid"]
    assert preflight(SandboxPolicy())["execution_ready"] is False
    with pytest.raises(RuntimeError, match="No host fallback"):
        execute_sample("anything")


def test_events_are_passive_and_errors_counted(tmp_path):
    file = tmp_path / "events.jsonl"
    file.write_text(json.dumps({"run_id": "test", "timestamp": "2099-01-01", "type": "syscall", "name": "connect", "pid": 1, "return_code": -1}), encoding="utf-8")
    report = analyze_events(file)
    assert report["syscall_counts"] == {"connect": 1}
    assert report["abnormalities"][0]["kind"] == "syscall_error"
    assert report["isolation_verified"] is False


def test_cli_offline_demo(tmp_path, capsys):
    db, output = tmp_path / "demo.sqlite", tmp_path / "artifacts"
    assert main(["--db", str(db), "demo", "--output", str(output)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["top_hit"] == "CVE-2099-1001"
    assert (output / "analysis" / "quality.json").exists()
    assert main(["--db", str(db), "demo", "--output", str(output)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["changed_sources"] == 0


def test_avd_exchange_file_and_invalid_shape(tmp_path):
    file = tmp_path / "avd.jsonl"
    data = {"source_id": "AVD-TEST-1", "url": "https://example.invalid/1", "aliases": ["CVE-2099-1001"], "fields": {"description": "example"}}
    file.write_text(json.dumps(data), encoding="utf-8")
    assert read_file("avd", file)[0].vuln_id == "CVE-2099-1001"
    with pytest.raises(ValueError, match="fields object"):
        parse("cnnvd", {"source_id": "1"})
