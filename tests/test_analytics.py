import json

from vulntools.analytics import (
    dataset_manifest_report,
    drift_report,
    effect_report,
    quality_report,
    read_dataset_manifest,
    read_effect_log,
    read_training_log,
    training_report,
    write_report,
)
from vulntools.demo import demo_sources
from vulntools.processing import process


def test_dataset_manifest_detects_leakage_duplicates_and_unknown_ids(tmp_path):
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(
        '\n'.join([
            '{"sample_id":"one","vuln_id":"CVE-2099-1001","family_id":"family-a","split":"train","labels":["major"],"modalities":["text"]}',
            '{"sample_id":"one","vuln_id":"CVE-2099-1001","family_id":"family-a","split":"test","labels":["rare"],"modalities":["poc"]}',
            '{"sample_id":"three","vuln_id":"CVE-2099-9999","family_id":"family-b","split":"train","labels":["major"],"modalities":["text"]}',
        ]) + '\n', encoding="utf-8",
    )
    rows, anomalies = read_dataset_manifest(manifest)
    report = dataset_manifest_report(rows, anomalies, known_vuln_ids={"CVE-2099-1001"}, rare_share=0.4)
    assert report["leakage_free"] is False
    assert report["anomaly_counts"]["duplicate_sample_id"] == 1
    assert report["anomaly_counts"]["vulnerability_split_leakage"] == 1
    assert report["anomaly_counts"]["family_split_leakage"] == 1
    assert report["anomaly_counts"]["unknown_vulnerability"] == 1
    assert report["imbalance"]["labels"]["rare_labels"] == ["rare"]


def test_training_report_summarizes_resources_and_eval_regression(tmp_path):
    log = tmp_path / "training.jsonl"
    log.write_text(
        '\n'.join([
            '{"run_id":"r1","step":1,"loss":2.0,"eval_loss":1.0,"throughput":10,"gpu_memory_mb":100}',
            '{"run_id":"r1","step":2,"loss":1.5,"eval_loss":0.8,"throughput":11,"gpu_memory_mb":110}',
            '{"run_id":"r1","step":3,"loss":1.2,"eval_loss":0.9,"throughput":12,"gpu_memory_mb":120}',
        ]), encoding="utf-8",
    )
    rows, anomalies = read_training_log(log)
    report = training_report(rows, anomalies)
    assert report["runs"]["r1"]["metrics"]["throughput"]["mean"] == 11
    assert report["runs"]["r1"]["best_eval"] == {"step": 2, "value": 0.8}
    assert report["anomaly_counts"]["eval_regression"] == 1


def test_training_directory_detects_runtime_failures_and_resource_anomalies(tmp_path):
    logs = tmp_path / "runs"
    logs.mkdir()
    first = [
        {"run_id": "r-live", "step": step, "loss": 2 - step / 10, "grad_norm": 1,
         "throughput": 100, "dataset_version": "v1", "model_version": "m1"}
        for step in range(1, 4)
    ]
    second = [
        {"run_id": "r-live", "step": step, "loss": 2 - step / 10,
         "grad_norm": 200 if step == 6 else 1, "throughput": 10,
         "dataset_version": "v2", "model_version": "m1",
         "status": "failed" if step == 6 else "running", "exit_reason": "oom" if step == 6 else None}
        for step in range(4, 7)
    ]
    (logs / "001.jsonl").write_text("\n".join(json.dumps(row) for row in first) + "\n", encoding="utf-8")
    (logs / "002.jsonl").write_text("\n".join(json.dumps(row) for row in second) + "\n", encoding="utf-8")
    rows, anomalies = read_training_log(logs)
    report = training_report(rows, anomalies)
    assert report["observations"] == 6
    assert report["anomaly_counts"]["dataset_version_changed"] == 1
    assert report["anomaly_counts"]["run_interrupted"] == 1
    assert report["anomaly_counts"]["gradient_spike"] == 1
    assert report["anomaly_counts"]["throughput_collapse"] == 1


def test_effect_report_uses_metric_direction_and_paired_seeds(tmp_path):
    log = tmp_path / "effect.jsonl"
    log.write_text(
        '\n'.join([
            '{"variant":"baseline","task":"x","metric":"error","direction":"minimize","seed":1,"dataset_version":"v1","value":0.4}',
            '{"variant":"injected","task":"x","metric":"error","direction":"minimize","seed":1,"dataset_version":"v1","value":0.3}',
            '{"variant":"baseline","task":"x","metric":"error","direction":"minimize","seed":2,"dataset_version":"v1","value":0.5}',
            '{"variant":"injected","task":"x","metric":"error","direction":"minimize","seed":2,"dataset_version":"v1","value":0.4}',
        ]), encoding="utf-8",
    )
    rows, anomalies = read_effect_log(log)
    comparison = effect_report(rows, anomalies)["comparisons"][0]
    assert round(comparison["paired_delta"]["mean"], 8) == 0.1
    assert comparison["outcome"] == "improved"
    assert comparison["evidence"] == "repeated_pairs"


def test_write_report_emits_audit_artifacts(tmp_path):
    records = process(demo_sources())
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text('{"sample_id":"one","vuln_id":"CVE-2099-1001","family_id":"f1","split":"train","labels":["CWE-22"],"modalities":["text"]}\n', encoding="utf-8")
    training = tmp_path / "training.jsonl"
    training.write_text('{"run_id":"r1","step":1,"loss":1.0}\n', encoding="utf-8")
    effect = tmp_path / "effect.jsonl"
    effect.write_text('{"variant":"baseline","metric":"f1","value":0.5}\n', encoding="utf-8")
    output = tmp_path / "report"
    report = write_report(records, output, dataset_manifest=str(manifest), training_log=str(training), effect_log=str(effect))
    assert report["schema"] == "vulntools/analytics/v2"
    assert report["metadata"]["dataset_id"]
    for name in ("quality.json", "records.csv", "anomalies.csv", "dataset-manifest.csv", "training.csv", "knowledge-effects.csv"):
        assert (output / name).exists()
    saved = json.loads((output / "quality.json").read_text(encoding="utf-8"))
    assert saved["overview"]["connected_inputs"]["effect_log"] is True
    drift_output = tmp_path / "drift-report"
    drifted = write_report(records, drift_output, baseline_report=str(output / "quality.json"))
    assert drifted["drift"]["status"] == "stable"
    assert (drift_output / "drift.csv").exists()


def test_quality_report_finds_alias_collisions():
    records = process(demo_sources())
    records[1]["aliases"].append("CVE-2099-1001")
    report = quality_report(records)
    assert report["anomaly_counts"]["alias_collision"] == 1


def test_distribution_drift_is_bounded_and_reports_categories():
    baseline = quality_report(process(demo_sources()))
    current = json.loads(json.dumps(baseline))
    current["dataset_id"] = "current"
    current["severity"] = {"critical": 3}
    current["modalities"]["image_embedding"] = 3
    report = drift_report(current, baseline, threshold=0.1)
    assert report["status"] == "alert"
    assert 0 <= report["dimensions"]["severity"]["js_divergence"] <= 1
    assert report["dimensions"]["severity"]["new_categories"] == ["critical"]
    assert report["anomaly_counts"]["distribution_drift"] >= 1
