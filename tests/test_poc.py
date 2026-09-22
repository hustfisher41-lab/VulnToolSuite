import csv

from vulntools.poc import import_exploitdb_directory, import_nuclei_directory
from vulntools.storage import Store


def test_nuclei_import_is_versioned_and_typed_as_detection(tmp_path):
    root = tmp_path / "nuclei"
    root.mkdir()
    template = root / "cve.yaml"
    template.write_text("""id: CVE-2026-9001
info:
  name: Example safe detector
  severity: high
  tags: cve,test
http:
  - method: GET
    path: [\"{{BaseURL}}/version\"]
    matchers:
      - type: word
        words: [\"example\"]
""", encoding="utf-8")
    with Store(tmp_path / "poc.sqlite") as store:
        first = import_nuclei_directory(store, root, commit_ref="abc123")
        assert first["matched_files"] == 1
        assert first["changed"] == 1
        assert store.poc_status() == {
            "artifacts": 1, "versions": 1, "links": 1, "unique_cves": 1,
            "linked_canonical_cves": 0, "content_bytes": template.stat().st_size,
            "by_source": {"nuclei": 1}, "by_type": {"detection_template": 1},
            "by_review_status": {"candidate": 1},
        }
        second = import_nuclei_directory(store, root, commit_ref="abc123")
        assert second["unchanged"] == 1 and second["versions_added"] == 0
        template.write_text(template.read_text(encoding="utf-8") + "# revised\n", encoding="utf-8")
        third = import_nuclei_directory(store, root, commit_ref="def456")
        assert third["changed"] == 1 and third["versions_added"] == 1
        assert store.poc_status()["versions"] == 2


def test_exploitdb_import_uses_index_cve_labels_and_keeps_code(tmp_path):
    root = tmp_path / "exploitdb"
    code = root / "exploits" / "linux" / "local" / "42.py"
    code.parent.mkdir(parents=True)
    code.write_text("print('static fixture; never execute')\n", encoding="utf-8")
    columns = ["id", "file", "description", "date_published", "author", "type",
               "platform", "verified", "codes", "aliases", "tags"]
    with (root / "files_exploits.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerow({"id": "42", "file": "exploits/linux/local/42.py",
                         "description": "Example CVE-2026-9002", "author": "tester",
                         "type": "local", "platform": "linux", "verified": "1",
                         "codes": "CVE-2026-9002"})
    with Store(tmp_path / "poc.sqlite") as store:
        result = import_exploitdb_directory(store, root, commit_ref="feedbeef")
        assert result["matched_files"] == 1 and result["links"] == 1
        row = store.db.execute("SELECT artifact_type,source_url,language FROM poc_artifacts").fetchone()
        assert tuple(row) == ("exploit_code", "https://www.exploit-db.com/exploits/42", "python")
        content = store.db.execute("SELECT content FROM poc_artifact_versions").fetchone()[0]
        assert "never execute" in content
