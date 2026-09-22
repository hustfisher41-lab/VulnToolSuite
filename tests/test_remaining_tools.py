import json
import hashlib
import time

import pytest

from vulntools.analytics import quality_report
from vulntools.demo import demo_sources
from vulntools.embedding import (
    DomainAdapterEncoder, HashEncoder, classify_text, cluster_records,
    fit_domain_adapter, generate_training_pairs,
)
from vulntools.enrichment import attach_ocr_artifact, attach_vision_artifact, enrich_missing
from vulntools.models import SourceRecord
from vulntools.processing import alignment_report, extract_modalities, process
from vulntools.sandbox import SandboxPolicy, preflight, run_in_vm
from vulntools.storage import Store
from vulntools.vision import encode_image_artifact


def test_multimodal_alignment_extracts_code_image_and_behaviors():
    value = """Issue details.\n```python\nimport requests\nopen('x', 'w')\n```\n<pre><code>system(&quot;id&quot;);</code></pre>\n![trace](https://example.invalid/trace.png)"""
    segments = extract_modalities(value)
    assert [item["modality"] for item in segments].count("code") == 2
    assert [item["modality"] for item in segments].count("image_reference") == 1
    assert "network" in segments[1]["representation"]["code_behavior"]["behaviors"]
    assert "filesystem" in segments[1]["representation"]["code_behavior"]["behaviors"]
    record = process([SourceRecord("cve", "CVE-2099-9001", "https://example.invalid/x", {}, fields={"description": value})])[0]
    report = alignment_report([record])
    assert report["aligned"] is True
    assert report["modalities"]["code"] == 2


def test_enrichment_applies_only_parsed_source_evidence(tmp_path):
    db = tmp_path / "enrich.sqlite"
    with Store(db) as store:
        store.save_sources([SourceRecord("cve", "CVE-2099-9002", "https://example.invalid/cve", {}, fields={"description": "incomplete"})])

        def fake_fetch(source, identifier, **kwargs):
            assert source == "nvd"
            assert identifier == "CVE-2099-9002"
            return SourceRecord("nvd", identifier, "https://example.invalid/nvd", {"source": "fixture"},
                                fields={"description": "incomplete", "severity": "high", "weaknesses": ["CWE-79"]})

        report = enrich_missing(store, sources=["nvd"], fetcher=fake_fetch)
        assert report["mode"] == "apply"
        assert report["improvements"][0]["filled_fields"] == ["weaknesses", "severity"]
        canonical = store.records()[0]
        assert canonical["fields"]["severity"] == "high"
        assert canonical["provenance"]["severity"][0]["source"] == "nvd"


def test_reviewed_ocr_artifact_becomes_aligned_evidence(tmp_path):
    artifact = tmp_path / "ocr.json"
    artifact.write_text(json.dumps({
        "schema_version": "vulntools/v1", "modality": "image", "content_hash": "a" * 64,
        "extractor": "fixture", "language": "eng", "path": "fixture.png", "text": "destination path must remain inside root",
    }), encoding="utf-8")
    with Store(tmp_path / "ocr.sqlite") as store:
        store.save_sources([SourceRecord("avd", "AVD-1", "https://example.invalid/avd", {}, fields={"description": "fixture"})])
        report = attach_ocr_artifact(store, "avd", "AVD-1", artifact)
        assert report["characters"] > 0
        canonical = store.records()[0]
        evidence = [item for item in canonical["evidence"] if item["modality"] == "image_transcript"]
        assert evidence[0]["representation"]["schema"] == "aligned/v1"


def test_native_vision_artifact_is_validated_and_aligned(tmp_path):
    image = tmp_path / "fixture.bin"
    image.write_bytes(b"fixture image bytes")

    class FakeVisionEncoder:
        manifest = {"provider": "fixture", "dimension": 3, "metric": "cosine",
                    "modality": "image", "native_vision_model": True}

        def encode_image(self, path):
            assert path == image.resolve()
            return [0.0, 0.6, 0.8]

    artifact_value = encode_image_artifact(image, FakeVisionEncoder())
    artifact = tmp_path / "vision.json"
    artifact.write_text(json.dumps(artifact_value), encoding="utf-8")
    with Store(tmp_path / "vision.sqlite") as store:
        store.save_sources([SourceRecord("avd", "AVD-2", "https://example.invalid/avd", {},
                                         fields={"description": "fixture"})])
        report = attach_vision_artifact(store, "avd", "AVD-2", artifact)
        assert report["dimension"] == 3
        canonical = store.records()[0]
        evidence = [item for item in canonical["evidence"] if item["modality"] == "image_embedding"]
        assert evidence[0]["representation"]["native_vision"] is True
        assert canonical["fields"]["image_embeddings"][0]["embedding"] == [0.0, 0.6, 0.8]


def test_component_entity_disambiguation_merges_compatible_ids_and_flags_conflicts():
    cve = SourceRecord("cve", "CVE-2099-9100", "https://example.invalid/cve", {}, fields={
        "description": "fixture", "components": [{
            "vendor": "Acme", "name": "Widget", "packageURL": "pkg:pypi/widget@1.0",
            "versions": [{"version": "1.0", "status": "affected"}],
        }],
    })
    nvd = SourceRecord("nvd", "CVE-2099-9100", "https://example.invalid/nvd", {}, fields={
        "components": [{
            "vendor": "ACME", "name": "Widget",
            "cpe": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
            "versions": [{"version": "1.1", "status": "affected"}],
        }],
    })
    merged = process([cve, nvd])[0]
    assert len(merged["fields"]["components"]) == 1
    component = merged["fields"]["components"][0]
    assert component["identity"]["basis"] == "purl"
    assert component["identity"]["cpes"] == ["cpe:2.3:a:acme:widget"]
    assert {item["version"] for item in component["versions"]} == {"1.0", "1.1"}

    conflicting = SourceRecord("avd", "AVD-9100", "https://example.invalid/avd", {},
        aliases=["CVE-2099-9100"], fields={"components": [{
            "vendor": "Acme", "name": "Widget", "packageURL": "pkg:npm/widget",
            "versions": [],
        }]})
    reviewed = process([cve, conflicting])[0]
    assert len(reviewed["fields"]["components"]) == 2
    assert reviewed["entity_review"][0]["kind"] == "conflicting_component_identifiers"
    assert quality_report([reviewed])["anomaly_counts"]["component_entity_review"] == 1


def test_domain_adapter_training_clustering_and_classification(tmp_path):
    records = process(demo_sources())
    pairs = generate_training_pairs(records)
    assert {pair["label"] for pair in pairs} == {0, 1}
    base = HashEncoder(64)
    model = tmp_path / "adapter.json"
    trained = fit_domain_adapter(base, pairs, model, epochs=2)
    assert trained["training"]["positive_pairs"] > 0
    adapter = DomainAdapterEncoder.load(base, model)
    assert adapter.manifest["domain_trained"] is True
    assert len(adapter.encode("archive traversal")) == 64
    clusters = cluster_records(records, adapter, clusters=2)
    assert sum(cluster["size"] for cluster in clusters["clusters"]) == 3
    predictions = classify_text(records, adapter, "unescaped HTML script", top_k=3)
    assert {item["label"] for item in predictions} == {"CWE-22", "CWE-79", "CWE-89"}


class FakeVMBackend:
    def __init__(self):
        self.submitted = False
        self.destroyed = False

    def capabilities(self):
        issued_at = int(time.time())
        digest = hashlib.sha256(b"fixture-acceptance").hexdigest()
        attestation = {
            "id": "acceptance-2026-09-14", "backend_id": "fixture-vm",
            "agent_version": "test", "issued_at": issued_at, "expires_at": issued_at + 300,
            "image_sha256": "1" * 64, "kernel_sha256": "2" * 64,
            "supervisor_sha256": "3" * 64, "acceptance_digest": digest,
            "signature": "fixture-not-verified-without-key",
        }
        return {
            "backend_id": "fixture-vm", "attestation_id": "acceptance-2026-09-14",
            "isolation": "vm", "guest_network": "disabled", "host_mounts": False,
            "readonly_base": True, "ephemeral_overlay": True, "external_watchdog": True,
            "syscall_monitor": True,
            "acceptance_tests": {
                "network_blocked": True, "host_fs_hidden": True, "timeout_kill": True,
                "resource_kill": True, "monitor_fail_closed": True, "overlay_destroyed": True,
                "watchdog_survives_disconnect": True, "orphan_recovery": True,
                "artifact_integrity": True,
            },
            "attestation": attestation,
        }

    def submit(self, name, content, sha256, policy):
        assert name == "harmless.txt" and content == b"fixture only\n"
        assert policy["network"] == "disabled" and len(sha256) == 64
        self.submitted = True
        return "fixture_run_01"

    def wait(self, run_id, timeout_seconds):
        assert run_id == "fixture_run_01" and timeout_seconds == 30
        return {"status": "succeeded", "exit_code": 0}

    def artifacts(self, run_id):
        events = b'{"run_id":"fixture_run_01","timestamp":"2026-09-14T00:00:00Z","type":"syscall","name":"read","pid":1,"return_code":4}\n'
        return {"events.jsonl": events, "stdout.txt": b"fixture\n", "result.json": b'{"exit_code":0}\n'}

    def destroy(self, run_id):
        self.destroyed = True


def test_vm_runner_requires_attestation_collects_events_and_destroys(tmp_path):
    sample = tmp_path / "harmless.txt"
    sample.write_bytes(b"fixture only\n")
    backend = FakeVMBackend()
    report = run_in_vm(sample, tmp_path / "artifacts", SandboxPolicy(), backend)
    assert backend.submitted and backend.destroyed
    assert report["execution_boundary"] == "independent_vm"
    assert report["destroyed"] is True
    assert report["event_analysis"]["syscall_counts"] == {"read": 1}
    assert (tmp_path / "artifacts" / "events.jsonl").exists()


def test_vm_runner_fails_closed_on_missing_capability(tmp_path):
    backend = FakeVMBackend()
    capabilities = backend.capabilities()
    capabilities["host_mounts"] = True
    assert preflight(SandboxPolicy(), capabilities)["execution_ready"] is False

    class UnsafeBackend(FakeVMBackend):
        def capabilities(self):
            return capabilities

    sample = tmp_path / "harmless.txt"
    sample.write_text("fixture", encoding="utf-8")
    unsafe = UnsafeBackend()
    with pytest.raises(RuntimeError, match="preflight failed"):
        run_in_vm(sample, tmp_path / "output", SandboxPolicy(), unsafe)
    assert unsafe.submitted is False


def test_vm_runner_destroys_vm_when_required_log_is_missing(tmp_path):
    class MissingLogBackend(FakeVMBackend):
        def artifacts(self, run_id):
            return {"stdout.txt": b"fixture\n"}

    sample = tmp_path / "harmless.txt"
    sample.write_bytes(b"fixture only\n")
    backend = MissingLogBackend()
    with pytest.raises(RuntimeError, match="omitted required"):
        run_in_vm(sample, tmp_path / "artifacts", SandboxPolicy(), backend)
    assert backend.destroyed is True
    assert not (tmp_path / "artifacts").exists()


def test_vm_runner_rejects_cross_run_events_before_publishing(tmp_path):
    class CrossRunBackend(FakeVMBackend):
        def artifacts(self, run_id):
            return {"events.jsonl": b'{"run_id":"another_run","timestamp":"2026-09-14T00:00:00Z","type":"signal"}\n'}

    sample = tmp_path / "harmless.txt"
    sample.write_bytes(b"fixture only\n")
    backend = CrossRunBackend()
    with pytest.raises(ValueError, match="run_id"):
        run_in_vm(sample, tmp_path / "artifacts", SandboxPolicy(), backend)
    assert backend.destroyed is True
    assert not (tmp_path / "artifacts").exists()
