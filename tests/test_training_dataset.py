import json

from vulntools.analytics import dataset_manifest_report, read_dataset_manifest
from vulntools.models import digest
from vulntools.storage import Store
from vulntools.training import _split, build_training_dataset
from scripts.validate_training_dataset import validate


def _record(cve, description):
    record = {
        "schema_version": "vulntools/v1", "vuln_id": cve, "aliases": [cve], "status": "active",
        "fields": {"title": cve, "description": description, "severity": "high",
                   "weaknesses": ["CWE-79"],
                   "components": [{"vendor": "Example", "name": "Widget", "versions": []}],
                   "attack_preconditions": None, "patch": None, "poc": None},
        "field_states": {"description": "present", "severity": "present", "weaknesses": "present",
                         "components": "present", "attack_preconditions": "missing",
                         "patch": "missing", "poc": "missing"},
        "provenance": {}, "conflicts": {}, "evidence": [], "entity_review": [],
        "references": [], "sources": [{"source": "cve", "source_id": cve,
                                          "url": f"https://example.invalid/{cve}", "status": "active",
                                          "raw_hash": "0" * 64}],
    }
    record["revision"] = digest(record)
    return record


def _poc(number, cve):
    content = f"# static training fixture {number}\nprint('not executed')\n"
    return {
        "artifact_id": digest(["exploitdb", str(number)]), "source": "exploitdb",
        "source_item_id": str(number), "artifact_type": "exploit_code",
        "title": f"Example exploit {number}", "source_url": f"https://example.invalid/{number}",
        "commit_ref": "abc", "local_path": f"{number}.py", "language": "python",
        "license": None, "review_status": "candidate", "content": content,
        "cve_ids": [cve], "link_relation": "claims_to_reproduce", "link_confidence": 0.9,
        "metadata": {"fixture": True},
    }


def test_training_export_supports_sft_preference_rag_and_leakage_checks(tmp_path):
    candidates = [f"CVE-2026-{number}" for number in range(9000, 9999)]
    first = candidates[0]
    same_split = [value for value in candidates[1:] if _split(value, "test-seed") == _split(first, "test-seed")]
    second, third = same_split[:2]
    records = [
        _record(first, "Stored input reaches an HTML response without output encoding and causes cross-site scripting."),
        _record(second, "A reflected parameter is returned into an HTML page without contextual output encoding."),
        _record(third, "Untrusted profile data is rendered in a page without output encoding in the affected product."),
    ]
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical(records)
        store.save_poc_artifacts([_poc(1, first), _poc(2, second), _poc(3, third)])
        report = build_training_dataset(store, tmp_path / "dataset", split_seed="test-seed",
                                        chunk_chars=256, chunk_overlap=16)

    assert report["counts"]["knowledge"] == 3
    assert report["counts"]["sft_classification"] == 3
    assert report["counts"]["sft_poc_association"] == 3
    assert report["counts"]["preference"] == 0
    assert report["counts"]["preference_candidates"] == 3
    assert report["counts"]["hard_negatives"] == 3
    assert report["quality"]["split_unit"] == "poc_and_duplicate_content_connected_cve_family"
    assert (tmp_path / "dataset/preference.jsonl").read_text(encoding="utf-8") == ""
    preference = _rows(tmp_path / "dataset/preference-candidates.jsonl")
    assert all(row["training_eligible"] is False for row in preference)
    assert all(row["requires_human_review"] for row in preference)
    assert all(row["preference_origin"].startswith("synthetic") for row in preference)
    rows, anomalies = read_dataset_manifest(tmp_path / "dataset/dataset-manifest.jsonl")
    quality = dataset_manifest_report(rows, anomalies, known_vuln_ids={first, second, third})
    assert quality["leakage_free"] is True
    assert quality["anomalies"] == []


def _rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_duplicate_code_groups_families_and_preserves_all_sources(tmp_path):
    first, second = "CVE-2026-9000", "CVE-2026-9001"
    one, two = _poc(1, first), _poc(2, second)
    two["content"] = one["content"].replace("\n", "  \n")
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical([_record(first, "First distinct description of a vulnerability affecting a test application."),
                                 _record(second, "Second distinct vulnerability description containing unrelated source assertions.")])
        store.save_poc_artifacts([one, two])
        report = build_training_dataset(store, tmp_path / "dataset")
    knowledge = _rows(tmp_path / "dataset/knowledge.jsonl")
    assert len({row["family_id"] for row in knowledge}) == 1
    code = [row for row in _rows(tmp_path / "dataset/rag-corpus.jsonl") if row["modality"] == "poc_code"]
    assert len(code) == 1
    assert code[0]["vuln_ids"] == [first, second]
    assert len(code[0]["metadata"]["source_provenance"]) == 2
    assert report["validation"]["status"] == "passed"
    assert report["counts"]["preference"] == 0


def test_duplicate_descriptions_and_shared_poc_stay_in_one_split(tmp_path):
    ids = ["CVE-2026-9000", "CVE-2026-9001", "CVE-2026-9002"]
    description = "Repeated source description of a test vulnerability without distinct identifying details."
    poc = _poc(1, ids[1])
    poc["cve_ids"] = ids[1:]
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical([_record(ids[0], description), _record(ids[1], description),
                                 _record(ids[2], "Distinct record joined to the other two records through its shared PoC artifact.")])
        store.save_poc_artifacts([poc])
        report = build_training_dataset(store, tmp_path / "dataset")
    rows = _rows(tmp_path / "dataset/knowledge.jsonl")
    assert len({row["family_id"] for row in rows}) == 1
    assert len({row["split"] for row in rows}) == 1
    assert report["counts"].get("hard_negatives", 0) == 0


def test_labels_are_grounded_candidates_unverified_and_rejected_excluded(tmp_path):
    cve = "CVE-2026-9000"
    record = _record(cve, "A source description long enough to meet the minimum training eligibility threshold.")
    record["fields"]["components"] = [{"name": "n/a"}, {"vendor": "Example", "name": "RealProduct"}]
    record["conflicts"] = {"severity": ["high", "low"]}
    record["fields"]["weaknesses"] = ["NVD-CWE-noinfo", "CWE-79"]
    candidate, rejected = _poc(1, cve), _poc(2, cve)
    rejected["review_status"] = "rejected"
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical([record])
        store.save_poc_artifacts([candidate, rejected])
        report = build_training_dataset(store, tmp_path / "dataset")
    sft = _rows(tmp_path / "dataset/sft.jsonl")
    metadata = next(row for row in sft if row["task"] == "grounded_metadata_extraction")
    answer = json.loads(metadata["messages"][-1]["content"])
    assert answer["severity"] is None
    assert answer["weaknesses"] == ["CWE-79"]
    assert answer["components"] == [{"vendor": "Example", "name": "RealProduct"}]
    assert "source_assertions" in metadata["messages"][1]["content"]
    poc = next(row for row in sft if row["task"] == "poc_claim_extraction")
    answer = json.loads(poc["messages"][-1]["content"])
    assert answer["upstream_claimed_association"] is True
    assert answer["replay_verified"] is False
    knowledge = _rows(tmp_path / "dataset/knowledge.jsonl")[0]
    assert len(knowledge["knowledge"]["poc_artifacts"]) == 1
    assert report["readiness"]["requirements_fully_met"] is False


def test_dataset_id_is_portable_and_unknown_labels_are_not_hard_negatives(tmp_path):
    with Store(tmp_path / "training.sqlite") as store:
        records = [_record(f"CVE-2026-{i}", f"Distinct source record number {i} with enough description text to qualify for export.")
                   for i in range(9000, 9004)]
        for record in records:
            record["fields"].update(severity=None, weaknesses=[], components=[{"name": "n/a"}])
        store.replace_canonical(records)
        one = build_training_dataset(store, tmp_path / "one")
        two = build_training_dataset(store, tmp_path / "two")
    assert one["dataset_id"] == two["dataset_id"]
    assert one["counts"].get("hard_negatives", 0) == 0
    assert one["counts"].get("sft_classification", 0) == 0


def test_duplicate_chunks_in_distinct_code_are_grouped(tmp_path):
    first, second = "CVE-2026-9000", "CVE-2026-9001"
    one, two = _poc(1, first), _poc(2, second)
    common = "# shared static fixture header\n" * 12
    one["content"] = common + "# first distinct ending\n"
    two["content"] = common + "# second distinct ending\n"
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical([_record(first, "First source description contains information about a distinct test vulnerability."),
                                 _record(second, "Second source description contains another unrelated test vulnerability for the fixture.")])
        store.save_poc_artifacts([one, two])
        report = build_training_dataset(store, tmp_path / "dataset", chunk_chars=256, chunk_overlap=16)
    rows = _rows(tmp_path / "dataset/knowledge.jsonl")
    assert len({row["family_id"] for row in rows}) == 1
    assert report["validation"]["status"] == "passed"


def test_independent_validator_checks_grounding_and_quarantine(tmp_path):
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical([_record("CVE-2026-9000", "A distinct source description with enough content to be included in the fixture export.")])
        store.save_poc_artifacts([_poc(1, "CVE-2026-9000")])
        build_training_dataset(store, tmp_path / "dataset")
    report = validate(tmp_path / "dataset")
    assert report["status"] == "passed"
    assert report["leakage"]["normalized_rag_content"] == 0


def test_independent_validator_detects_tampered_file(tmp_path):
    with Store(tmp_path / "training.sqlite") as store:
        store.replace_canonical([_record("CVE-2026-9000", "A distinct source description with enough content to be included in the fixture export.")])
        build_training_dataset(store, tmp_path / "dataset")
    path = tmp_path / "dataset/rag-corpus.jsonl"
    rows = _rows(path)
    rows[0]["text"] = "Tampered text without a matching hash"
    path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    report = validate(tmp_path / "dataset")
    assert report["status"] == "failed"
    assert any("snapshot mismatch" in error for error in report["errors"])
