"""Reproducible dataset, training and knowledge-injection analytics."""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
from typing import Any, Iterable

from .models import FIELDS, canonical_json

TRAINING_METRICS = (
    "loss", "eval_loss", "learning_rate", "grad_norm",
    "throughput", "gpu_memory_mb", "gpu_util_percent", "cpu_percent", "cpu_memory_mb",
    "disk_read_mb_s", "disk_write_mb_s",
)
VALID_SPLITS = {"train", "validation", "test"}


def _numeric_summary(values: Iterable[float]) -> dict[str, float | int | None]:
    clean = sorted(float(value) for value in values if math.isfinite(float(value)))
    if not clean:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None, "p95": None}

    def percentile(fraction: float) -> float:
        position = (len(clean) - 1) * fraction
        lower = math.floor(position)
        upper = math.ceil(position)
        if lower == upper:
            return clean[lower]
        return clean[lower] * (upper - position) + clean[upper] * (position - lower)

    return {
        "count": len(clean), "min": clean[0], "max": clean[-1],
        "mean": statistics.fmean(clean), "median": statistics.median(clean),
        "p95": percentile(0.95),
    }


def _imbalance(counts: Counter[str] | dict[str, int], rare_share: float) -> dict[str, Any]:
    values = {str(key): int(value) for key, value in counts.items()}
    total = sum(values.values())
    nonzero = [value for value in values.values() if value > 0]
    return {
        "total_assignments": total,
        "classes": len(values),
        "largest_to_smallest_ratio": max(nonzero) / min(nonzero) if nonzero else None,
        "rare_labels": sorted(key for key, value in values.items() if total and value / total < rare_share),
        "rare_share_threshold": rare_share,
    }


def quality_report(records: list[dict[str, Any]], rare_share: float = 0.05) -> dict[str, Any]:
    """Summarize canonical-record coverage, distributions and reviewable anomalies."""
    if not 0 <= rare_share <= 1:
        raise ValueError("rare_share must be between 0 and 1")
    active = [record for record in records if record.get("status") == "active"]
    missing = {
        name: sum(record.get("field_states", {}).get(name) == "missing" for record in active)
        for name in FIELDS
    }
    conflicts = {
        name: sum(name in record.get("conflicts", {}) for record in active)
        for name in FIELDS
    }
    sources = Counter(
        source.get("source", "unknown")
        for record in active for source in record.get("sources", [])
    )
    severity = Counter(str(record.get("fields", {}).get("severity") or "unknown") for record in active)
    weaknesses = Counter(
        weakness
        for record in active
        for weakness in (record.get("fields", {}).get("weaknesses") or ["unknown"])
    )
    modalities = Counter(
        evidence.get("modality", "unknown")
        for record in active for evidence in record.get("evidence", [])
    )
    components = Counter()
    description_lengths: list[float] = []
    alias_owners: dict[str, set[str]] = defaultdict(set)
    anomalies: list[dict[str, Any]] = []
    for record in active:
        vuln_id = str(record.get("vuln_id", ""))
        fields = record.get("fields", {})
        description_lengths.append(len(str(fields.get("description") or "")))
        for component in fields.get("components") or []:
            if isinstance(component, dict):
                name = component.get("name") or component.get("product") or "unknown"
            else:
                name = component
            components[str(name)] += 1
        for alias in [vuln_id, *(record.get("aliases") or [])]:
            if alias:
                alias_owners[str(alias).upper()].add(vuln_id)
        missing_core = [name for name in ("description", "components", "severity") if record.get("field_states", {}).get(name) == "missing"]
        if missing_core:
            anomalies.append({"kind": "missing_core_fields", "vuln_id": vuln_id, "fields": missing_core})
        if record.get("conflicts"):
            anomalies.append({"kind": "source_conflict", "vuln_id": vuln_id, "fields": sorted(record["conflicts"])})
        for finding in record.get("entity_review") or []:
            anomalies.append({"kind": "component_entity_review", "vuln_id": vuln_id,
                              "reason": finding.get("kind", "unspecified"), "finding": finding})
        cvss_value = fields.get("cvss")
        if isinstance(cvss_value, dict):
            score = cvss_value.get("baseScore", cvss_value.get("score"))
            if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10):
                anomalies.append({"kind": "invalid_cvss", "vuln_id": vuln_id, "value": score})
    for alias, owners in sorted(alias_owners.items()):
        if len(owners) > 1:
            anomalies.append({"kind": "alias_collision", "alias": alias, "vuln_ids": sorted(owners)})

    identity = sorted((record.get("vuln_id"), record.get("revision")) for record in records)
    return {
        "dataset_id": hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest(),
        "records": len(records), "active": len(active), "rejected": len(records) - len(active),
        "sources": dict(sources), "severity": dict(severity), "weaknesses": dict(weaknesses),
        "modalities": dict(modalities), "components": dict(components),
        "missing_fields": missing, "conflicted_fields": conflicts,
        "coverage": {name: (len(active) - count) / len(active) if active else None for name, count in missing.items()},
        "description_length": _numeric_summary(description_lengths),
        "imbalance": {
            "severity": _imbalance(severity, rare_share),
            "weaknesses": _imbalance(weaknesses, rare_share),
            "components": _imbalance(components, rare_share),
        },
        "anomalies": anomalies,
        "anomaly_counts": dict(Counter(item["kind"] for item in anomalies)),
        "conflicted_records": [record["vuln_id"] for record in active if record.get("conflicts")],
        "notes": [
            "Counts describe source assertions, not verified ground truth.",
            "Missing data stays unknown; it is not a negative label.",
            "Rare-label findings are triage signals and depend on the configured share threshold.",
        ],
    }


def _distribution(values: dict[str, Any], categories: list[str]) -> list[float]:
    counts = [max(0.0, float(values.get(category, 0))) for category in categories]
    total = sum(counts)
    return [value / total for value in counts] if total else [0.0 for _ in counts]


def _js_divergence(left: list[float], right: list[float]) -> float:
    middle = [(a + b) / 2 for a, b in zip(left, right)]

    def divergence(values: list[float]) -> float:
        return sum(value * math.log2(value / center) for value, center in zip(values, middle) if value and center)

    return (divergence(left) + divergence(right)) / 2


def drift_report(current: dict[str, Any], baseline: dict[str, Any], threshold: float = 0.10) -> dict[str, Any]:
    """Compare two quality snapshots using bounded, reproducible distribution metrics."""
    if not 0 < threshold <= 1:
        raise ValueError("drift threshold must be in (0, 1]")
    if baseline.get("schema") == "vulntools/analytics/v2":
        baseline = baseline.get("metadata") or {}
    if not isinstance(baseline, dict) or not isinstance(baseline.get("dataset_id"), str):
        raise ValueError("Baseline report must be a quality report or vulntools/analytics/v2 report")
    dimensions, details, anomalies = {}, [], []
    for name in ("sources", "severity", "weaknesses", "modalities", "components"):
        old_values = baseline.get(name) or {}
        new_values = current.get(name) or {}
        if not isinstance(old_values, dict) or not isinstance(new_values, dict):
            raise ValueError(f"Drift dimension {name} must be an object")
        categories = sorted(set(map(str, old_values)) | set(map(str, new_values)))
        old_distribution = _distribution(old_values, categories)
        new_distribution = _distribution(new_values, categories)
        js = _js_divergence(old_distribution, new_distribution)
        total_variation = sum(abs(a - b) for a, b in zip(old_distribution, new_distribution)) / 2
        rows = []
        for category, old_share, new_share in zip(categories, old_distribution, new_distribution):
            row = {"dimension": name, "category": category, "baseline_share": old_share,
                   "current_share": new_share, "share_delta": new_share - old_share}
            rows.append(row)
            details.append(row)
        dimensions[name] = {
            "js_divergence": js, "total_variation": total_variation,
            "baseline_assignments": sum(float(value) for value in old_values.values()),
            "current_assignments": sum(float(value) for value in new_values.values()),
            "new_categories": sorted(set(map(str, new_values)) - set(map(str, old_values))),
            "dropped_categories": sorted(set(map(str, old_values)) - set(map(str, new_values))),
            "categories": rows,
        }
        if js >= threshold:
            anomalies.append({"kind": "distribution_drift", "dimension": name,
                              "js_divergence": js, "threshold": threshold})
    coverage = {}
    for field in sorted(set(baseline.get("coverage") or {}) | set(current.get("coverage") or {})):
        old = (baseline.get("coverage") or {}).get(field)
        new = (current.get("coverage") or {}).get(field)
        delta = float(new) - float(old) if old is not None and new is not None else None
        coverage[field] = {"baseline": old, "current": new, "delta": delta}
        if delta is not None and abs(delta) >= threshold:
            anomalies.append({"kind": "coverage_drift", "field": field, "delta": delta,
                              "threshold": threshold})
    return {
        "status": "alert" if anomalies else "stable", "threshold": threshold,
        "baseline_dataset_id": baseline["dataset_id"], "current_dataset_id": current.get("dataset_id"),
        "baseline_records": baseline.get("records"), "current_records": current.get("records"),
        "dimensions": dimensions, "coverage": coverage, "details": details,
        "anomalies": anomalies, "anomaly_counts": dict(Counter(item["kind"] for item in anomalies)),
        "notes": [
            "Jensen-Shannon divergence is bounded between 0 and 1 with base-2 logarithms.",
            "Drift is an investigation signal, not proof of data or model degradation.",
        ],
    }


def _read_jsonl(path: str | Path, label: str) -> list[tuple[int, dict[str, Any]]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} line {line_no}: invalid JSON") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{label} line {line_no}: expected a JSON object")
        rows.append((line_no, row))
    return rows


def read_dataset_manifest(path: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read sample-level split metadata without loading or executing sample content."""
    rows, anomalies = [], []
    for line_no, row in _read_jsonl(path, "Dataset manifest"):
        sample_id = str(row.get("sample_id") or "").strip()
        vuln_id = str(row.get("vuln_id") or "").strip().upper()
        family_id = str(row.get("family_id") or "").strip()
        split = str(row.get("split") or "").strip().lower()
        labels_value = row.get("labels", [])
        modalities_value = row.get("modalities", [])
        labels = [labels_value] if isinstance(labels_value, str) else labels_value
        modalities = [modalities_value] if isinstance(modalities_value, str) else modalities_value
        if not sample_id:
            anomalies.append({"line": line_no, "kind": "missing_sample_id"})
        if not vuln_id:
            anomalies.append({"line": line_no, "kind": "missing_vuln_id", "sample_id": sample_id})
        if split not in VALID_SPLITS:
            anomalies.append({"line": line_no, "kind": "invalid_split", "sample_id": sample_id, "value": split})
        if not isinstance(labels, list) or any(not isinstance(value, str) or not value.strip() for value in labels):
            anomalies.append({"line": line_no, "kind": "invalid_labels", "sample_id": sample_id})
            labels = []
        if not isinstance(modalities, list) or any(not isinstance(value, str) or not value.strip() for value in modalities):
            anomalies.append({"line": line_no, "kind": "invalid_modalities", "sample_id": sample_id})
            modalities = []
        weight = row.get("weight", 1.0)
        if isinstance(weight, bool) or not isinstance(weight, (int, float)) or not math.isfinite(weight) or weight <= 0:
            anomalies.append({"line": line_no, "kind": "invalid_weight", "sample_id": sample_id})
            weight = None
        rows.append({
            "line": line_no, "sample_id": sample_id, "vuln_id": vuln_id,
            "family_id": family_id, "split": split,
            "labels": [value.strip() for value in labels],
            "modalities": [value.strip() for value in modalities], "weight": weight,
        })
    return rows, anomalies


def dataset_manifest_report(
    rows: list[dict[str, Any]],
    anomalies: list[dict[str, Any]] | None = None,
    *,
    known_vuln_ids: set[str] | None = None,
    rare_share: float = 0.05,
) -> dict[str, Any]:
    """Detect duplicates, split leakage, unknown references and class imbalance."""
    findings = list(anomalies or [])
    sample_ids: dict[str, list[int]] = defaultdict(list)
    vuln_splits: dict[str, set[str]] = defaultdict(set)
    family_splits: dict[str, set[str]] = defaultdict(set)
    split_counts, label_counts, modality_counts = Counter(), Counter(), Counter()
    labels_by_split: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        if row["sample_id"]:
            sample_ids[row["sample_id"]].append(row["line"])
        if row["split"] in VALID_SPLITS:
            split_counts[row["split"]] += 1
            if row["vuln_id"]:
                vuln_splits[row["vuln_id"]].add(row["split"])
            if row["family_id"]:
                family_splits[row["family_id"]].add(row["split"])
        for label in row["labels"]:
            label_counts[label] += 1
            if row["split"] in VALID_SPLITS:
                labels_by_split[row["split"]][label] += 1
        modality_counts.update(row["modalities"])
        if known_vuln_ids is not None and row["vuln_id"] and row["vuln_id"] not in known_vuln_ids:
            findings.append({"line": row["line"], "kind": "unknown_vulnerability", "sample_id": row["sample_id"], "vuln_id": row["vuln_id"]})
    for sample_id, lines in sample_ids.items():
        if len(lines) > 1:
            findings.append({"kind": "duplicate_sample_id", "sample_id": sample_id, "lines": lines})
    for vuln_id, splits in vuln_splits.items():
        if len(splits) > 1:
            findings.append({"kind": "vulnerability_split_leakage", "vuln_id": vuln_id, "splits": sorted(splits)})
    for family_id, splits in family_splits.items():
        if len(splits) > 1:
            findings.append({"kind": "family_split_leakage", "family_id": family_id, "splits": sorted(splits)})
    return {
        "samples": len(rows), "splits": dict(split_counts), "labels": dict(label_counts),
        "labels_by_split": {key: dict(value) for key, value in labels_by_split.items()},
        "modalities": dict(modality_counts),
        "imbalance": {"labels": _imbalance(label_counts, rare_share), "modalities": _imbalance(modality_counts, rare_share)},
        "anomalies": findings, "anomaly_counts": dict(Counter(item["kind"] for item in findings)),
        "leakage_free": not any(item["kind"].endswith("split_leakage") for item in findings),
    }


def read_training_log(path: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read one JSONL file or an append-only directory of exported run logs."""
    rows, anomalies = [], []
    previous: dict[str, float] = {}
    source_path = Path(path)
    inputs = sorted(source_path.rglob("*.jsonl")) if source_path.is_dir() else [source_path]
    if not inputs:
        raise ValueError("Training log directory contains no JSONL files")
    source_rows = [(item, line_no, row) for item in inputs for line_no, row in _read_jsonl(item, "Training log")]
    for input_path, line_no, row in source_rows:
        run_id = str(row.get("run_id", "default"))
        step = row.get("step")
        if isinstance(step, bool) or not isinstance(step, (int, float)) or not math.isfinite(step) or step < 0:
            raise ValueError(f"Training line {line_no}: step must be finite and nonnegative")
        if run_id in previous and step <= previous[run_id]:
            anomalies.append({"file": str(input_path), "line": line_no, "run_id": run_id, "kind": "non_increasing_step"})
        previous[run_id] = step
        clean: dict[str, Any] = {"file": str(input_path), "line": line_no, "run_id": run_id, "step": step}
        for name in TRAINING_METRICS:
            value = row.get(name)
            if value is None:
                clean[name] = None
            elif isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                clean[name] = None
                anomalies.append({"file": str(input_path), "line": line_no, "run_id": run_id, "kind": "invalid_metric", "metric": name})
            else:
                clean[name] = float(value)
                if name in {"learning_rate", "grad_norm", "throughput", "gpu_memory_mb", "gpu_util_percent",
                            "cpu_percent", "cpu_memory_mb", "disk_read_mb_s", "disk_write_mb_s"} and value < 0:
                    anomalies.append({"file": str(input_path), "line": line_no, "run_id": run_id, "kind": "negative_metric", "metric": name})
                if name in {"cpu_percent", "gpu_util_percent"} and value > 100:
                    anomalies.append({"file": str(input_path), "line": line_no, "run_id": run_id, "kind": "out_of_range_metric", "metric": name})
        clean["dataset_version"] = row.get("dataset_version")
        clean["model_version"] = row.get("model_version")
        clean["timestamp"] = row.get("timestamp")
        clean["status"] = str(row.get("status") or "running").casefold()
        clean["exit_reason"] = row.get("exit_reason")
        if clean["status"] not in {"running", "succeeded", "failed", "cancelled"}:
            anomalies.append({"file": str(input_path), "line": line_no, "run_id": run_id,
                              "kind": "invalid_run_status", "value": clean["status"]})
        rows.append(clean)
    return rows, anomalies


def _slope(points: list[tuple[float, float]]) -> float | None:
    if len(points) < 2:
        return None
    mean_x = statistics.fmean(point[0] for point in points)
    mean_y = statistics.fmean(point[1] for point in points)
    denominator = sum((point[0] - mean_x) ** 2 for point in points)
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator if denominator else None


def training_report(rows: list[dict[str, Any]], anomalies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    findings = list(anomalies or [])
    run_reports: dict[str, Any] = {}
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_run[row["run_id"]].append(row)
    for run_id, run_rows in sorted(by_run.items()):
        ordered = sorted(run_rows, key=lambda item: item["step"])
        metrics = {name: _numeric_summary(row[name] for row in ordered if row[name] is not None) for name in TRAINING_METRICS}
        eval_points = [(row["step"], row["eval_loss"]) for row in ordered if row["eval_loss"] is not None]
        loss_points = [(row["step"], row["loss"]) for row in ordered if row["loss"] is not None]
        tail = loss_points[max(0, len(loss_points) // 2):]
        best_eval = min(eval_points, key=lambda point: point[1]) if eval_points else None
        final_gap = None
        paired = [row for row in ordered if row["loss"] is not None and row["eval_loss"] is not None]
        if paired:
            final_gap = paired[-1]["eval_loss"] - paired[-1]["loss"]
        if len(eval_points) >= 3 and eval_points[-1][1] > min(value for _, value in eval_points) * 1.02:
            findings.append({"run_id": run_id, "kind": "eval_regression", "best_step": best_eval[0], "last_step": eval_points[-1][0]})
        dataset_versions = sorted({str(row["dataset_version"]) for row in ordered if row.get("dataset_version")})
        model_versions = sorted({str(row["model_version"]) for row in ordered if row.get("model_version")})
        if len(dataset_versions) > 1:
            findings.append({"run_id": run_id, "kind": "dataset_version_changed", "versions": dataset_versions})
        if len(model_versions) > 1:
            findings.append({"run_id": run_id, "kind": "model_version_changed", "versions": model_versions})
        failed_rows = [row for row in ordered if row.get("status") in {"failed", "cancelled"}]
        if failed_rows:
            findings.append({"run_id": run_id, "kind": "run_interrupted", "status": failed_rows[-1]["status"],
                             "step": failed_rows[-1]["step"], "exit_reason": failed_rows[-1].get("exit_reason")})
        gradients = [row["grad_norm"] for row in ordered if row["grad_norm"] is not None and row["grad_norm"] >= 0]
        if len(gradients) >= 3:
            median_gradient = statistics.median(gradients)
            if max(gradients) > max(100.0, median_gradient * 10):
                findings.append({"run_id": run_id, "kind": "gradient_spike", "maximum": max(gradients),
                                 "median": median_gradient})
        throughputs = [row["throughput"] for row in ordered if row["throughput"] is not None]
        if len(throughputs) >= 6:
            window = max(1, len(throughputs) // 3)
            first_mean = statistics.fmean(throughputs[:window])
            last_mean = statistics.fmean(throughputs[-window:])
            if first_mean > 0 and last_mean < first_mean * 0.5:
                findings.append({"run_id": run_id, "kind": "throughput_collapse",
                                 "initial_mean": first_mean, "final_mean": last_mean})
        changes = [loss_points[index][1] - loss_points[index - 1][1] for index in range(1, len(loss_points))]
        run_reports[run_id] = {
            "observations": len(ordered), "first_step": ordered[0]["step"], "last_step": ordered[-1]["step"],
            "dataset_versions": dataset_versions, "model_versions": model_versions,
            "last_status": ordered[-1].get("status"), "last_timestamp": ordered[-1].get("timestamp"),
            "metrics": metrics, "best_eval": {"step": best_eval[0], "value": best_eval[1]} if best_eval else None,
            "tail_loss_slope": _slope(tail), "final_generalization_gap": final_gap,
            "loss_change_std": statistics.stdev(changes) if len(changes) >= 2 else None,
        }
    return {
        "observations": len(rows), "runs": run_reports, "anomalies": findings,
        "anomaly_counts": dict(Counter(item["kind"] for item in findings)),
        "notes": ["Curve diagnostics are triage signals; they do not establish model quality or convergence."],
    }


def read_effect_log(path: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read repeated baseline/knowledge-injection evaluation observations."""
    rows, anomalies = [], []
    for line_no, row in _read_jsonl(path, "Effect log"):
        clean = {
            "line": line_no, "variant": str(row.get("variant") or "").strip(),
            "task": str(row.get("task") or "overall").strip(),
            "metric": str(row.get("metric") or "").strip(),
            "direction": str(row.get("direction") or "maximize").strip().lower(),
            "seed": str(row.get("seed") if row.get("seed") is not None else "default"),
            "dataset_version": str(row.get("dataset_version") or "unspecified"),
            "value": row.get("value"),
        }
        for required in ("variant", "metric"):
            if not clean[required]:
                anomalies.append({"line": line_no, "kind": f"missing_{required}"})
        if clean["direction"] not in {"maximize", "minimize"}:
            anomalies.append({"line": line_no, "kind": "invalid_direction", "value": clean["direction"]})
        value = clean["value"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            anomalies.append({"line": line_no, "kind": "invalid_effect_value"})
            clean["value"] = None
        else:
            clean["value"] = float(value)
        rows.append(clean)
    return rows, anomalies


def _mean_ci(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean": None, "std": None, "ci95": [None, None]}
    mean = statistics.fmean(values)
    std = statistics.stdev(values) if len(values) >= 2 else None
    margin = 1.96 * std / math.sqrt(len(values)) if std is not None else None
    return {"count": len(values), "mean": mean, "std": std, "ci95": [mean - margin, mean + margin] if margin is not None else [None, None]}


def effect_report(
    rows: list[dict[str, Any]],
    anomalies: list[dict[str, Any]] | None = None,
    *,
    baseline_variant: str = "baseline",
) -> dict[str, Any]:
    """Compare variants with seed- and dataset-paired deltas against a named baseline."""
    findings = list(anomalies or [])
    valid = [row for row in rows if row["value"] is not None and row["direction"] in {"maximize", "minimize"} and row["variant"] and row["metric"]]
    groups: dict[tuple[str, str, str, str], list[float]] = defaultdict(list)
    indexed: dict[tuple[str, str, str, str, str], float] = {}
    for row in valid:
        groups[(row["task"], row["metric"], row["direction"], row["variant"])].append(row["value"])
        key = (row["task"], row["metric"], row["variant"], row["seed"], row["dataset_version"])
        if key in indexed:
            findings.append({"line": row["line"], "kind": "duplicate_effect_observation", "key": list(key)})
        indexed[key] = row["value"]
    summaries, comparisons = [], []
    for (task, metric, direction, variant), values in sorted(groups.items()):
        summaries.append({"task": task, "metric": metric, "direction": direction, "variant": variant, **_mean_ci(values)})
        if variant == baseline_variant:
            continue
        deltas = []
        for row in valid:
            if row["task"] != task or row["metric"] != metric or row["variant"] != variant:
                continue
            baseline_key = (task, metric, baseline_variant, row["seed"], row["dataset_version"])
            if baseline_key in indexed:
                baseline = indexed[baseline_key]
                deltas.append(row["value"] - baseline if direction == "maximize" else baseline - row["value"])
        stats = _mean_ci(deltas)
        low, high = stats["ci95"]
        if low is not None and low > 0:
            outcome = "improved"
        elif high is not None and high < 0:
            outcome = "regressed"
        else:
            outcome = "unchanged_or_uncertain"
        comparisons.append({
            "task": task, "metric": metric, "direction": direction,
            "variant": variant, "baseline": baseline_variant,
            "paired_delta": stats, "outcome": outcome,
            "evidence": "repeated_pairs" if len(deltas) >= 2 else "insufficient_pairs",
        })
    return {
        "observations": len(rows), "baseline_variant": baseline_variant,
        "summaries": summaries, "comparisons": comparisons,
        "anomalies": findings, "anomaly_counts": dict(Counter(item["kind"] for item in findings)),
        "notes": [
            "Positive paired delta always means better after applying metric direction.",
            "The normal-approximation interval is descriptive and is not a statistical-significance claim.",
            "Use frozen data, identical evaluation protocols and repeated seeds for effect conclusions.",
        ],
    }


def _write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: canonical_json(value) if isinstance(value, (list, dict)) else value for key, value in row.items()})


def _write_charts(output: Path, report: dict[str, Any], training_rows: list[dict[str, Any]], effect: dict[str, Any] | None) -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("Install the charts extra to create figures") from exc

    created = []
    fig, axes = plt.subplots(2, 2, figsize=(14, 9), layout="constrained")
    missing = report["metadata"]["missing_fields"]
    axes[0, 0].barh(list(missing), list(missing.values()), color="#176b87")
    axes[0, 0].set_title("Missing metadata fields")
    axes[0, 0].set_xlabel("Active records")
    severity = report["metadata"]["severity"]
    axes[0, 1].bar(list(severity), list(severity.values()), color="#bd5d38")
    axes[0, 1].set_title("Severity distribution")
    axes[0, 1].tick_params(axis="x", rotation=25)
    sources = report["metadata"]["sources"]
    axes[1, 0].bar(list(sources), list(sources.values()), color="#4f7cac")
    axes[1, 0].set_title("Source assertions")
    distribution = report.get("dataset", {}).get("splits") or report["metadata"]["modalities"]
    axes[1, 1].bar(list(distribution), list(distribution.values()), color="#6b8e23")
    axes[1, 1].set_title("Dataset splits" if report.get("dataset") else "Evidence modalities")
    axes[1, 1].tick_params(axis="x", rotation=25)
    fig.suptitle("Vulnerability data quality", fontsize=16)
    quality_path = output / "quality.png"
    fig.savefig(quality_path, dpi=160)
    plt.close(fig)
    created.append(quality_path.name)

    if training_rows:
        fig, axes = plt.subplots(3, 2, figsize=(14, 11), layout="constrained")
        for axis, metric in zip(axes.flat, ("loss", "eval_loss", "learning_rate", "grad_norm", "throughput", "gpu_memory_mb")):
            for run_id in sorted({row["run_id"] for row in training_rows}):
                points = sorted((row for row in training_rows if row["run_id"] == run_id and row[metric] is not None), key=lambda row: row["step"])
                if points:
                    axis.plot([row["step"] for row in points], [row[metric] for row in points], marker="o", markersize=3, label=run_id)
            axis.set_title(metric.replace("_", " ").title())
            axis.set_xlabel("Step")
            axis.grid(alpha=0.25)
            if len(axis.lines) > 1:
                axis.legend()
        fig.suptitle("Training diagnostics", fontsize=16)
        training_path = output / "training.png"
        fig.savefig(training_path, dpi=160)
        plt.close(fig)
        created.append(training_path.name)

    if effect and effect["comparisons"]:
        comparisons = effect["comparisons"]
        labels = [f'{row["variant"]} · {row["task"]}/{row["metric"]}' for row in comparisons]
        values = [row["paired_delta"]["mean"] or 0.0 for row in comparisons]
        errors = []
        for row, value in zip(comparisons, values):
            low, high = row["paired_delta"]["ci95"]
            errors.append([0.0, 0.0] if low is None else [value - low, high - value])
        fig_height = max(4.5, 0.55 * len(labels) + 2)
        fig, axis = plt.subplots(figsize=(14, fig_height), layout="constrained")
        y = list(range(len(labels)))
        axis.barh(y, values, color=["#2a9d8f" if value >= 0 else "#d1495b" for value in values], alpha=0.85)
        for index, (value, error) in enumerate(zip(values, errors)):
            if any(error):
                axis.errorbar(value, index, xerr=[[error[0]], [error[1]]], color="#222222", capsize=4)
        axis.axvline(0, color="#222222", linewidth=1)
        axis.set_yticks(y, labels)
        axis.set_xlabel("Paired improvement over baseline (positive is better)")
        axis.set_title("Knowledge injection effect")
        axis.grid(axis="x", alpha=0.25)
        effect_path = output / "knowledge-effects.png"
        fig.savefig(effect_path, dpi=160)
        plt.close(fig)
        created.append(effect_path.name)
    drift = report.get("drift") or {}
    if drift.get("status") in {"stable", "alert"}:
        dimensions = drift.get("dimensions") or {}
        coverage = drift.get("coverage") or {}
        fig, axes = plt.subplots(1, 2, figsize=(14, 5.5), layout="constrained")
        names = list(dimensions)
        values = [dimensions[name]["js_divergence"] for name in names]
        axes[0].barh(names, values, color=["#d1495b" if value >= drift["threshold"] else "#2a9d8f" for value in values])
        axes[0].axvline(drift["threshold"], color="#222222", linestyle="--", linewidth=1)
        axes[0].set_xlim(0, max([drift["threshold"] * 1.2, *values, 0.05]))
        axes[0].set_title("Distribution drift (Jensen-Shannon)")
        axes[0].set_xlabel("Divergence")
        fields = list(coverage)
        deltas = [coverage[field]["delta"] or 0.0 for field in fields]
        axes[1].barh(fields, deltas, color=["#d1495b" if abs(value) >= drift["threshold"] else "#4f7cac" for value in deltas])
        axes[1].axvline(0, color="#222222", linewidth=1)
        axes[1].set_title("Field coverage change")
        axes[1].set_xlabel("Current − baseline")
        drift_path = output / "drift.png"
        fig.savefig(drift_path, dpi=160)
        plt.close(fig)
        created.append(drift_path.name)
    return created


def write_report(
    records: list[dict[str, Any]],
    output: str | Path,
    *,
    training_log: str | None = None,
    dataset_manifest: str | None = None,
    effect_log: str | None = None,
    baseline_report: str | None = None,
    baseline_variant: str = "baseline",
    rare_share: float = 0.05,
    drift_threshold: float = 0.10,
    charts: bool = False,
) -> dict[str, Any]:
    """Build a machine-readable report, audit tables and optional publication-ready PNGs."""
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    metadata = quality_report(records, rare_share)
    report: dict[str, Any] = {"schema": "vulntools/analytics/v2", "metadata": metadata}
    # Preserve v1 top-level keys for API and caller compatibility.
    report.update({key: value for key, value in metadata.items() if key not in {"anomalies", "notes"}})

    dataset_rows: list[dict[str, Any]] = []
    if dataset_manifest:
        dataset_rows, dataset_anomalies = read_dataset_manifest(dataset_manifest)
        known = {str(record.get("vuln_id", "")).upper() for record in records}
        report["dataset"] = dataset_manifest_report(dataset_rows, dataset_anomalies, known_vuln_ids=known, rare_share=rare_share)
    else:
        report["dataset"] = {"status": "not_connected", "anomalies": []}

    training_rows: list[dict[str, Any]] = []
    if training_log:
        training_rows, training_anomalies = read_training_log(training_log)
        report["training"] = training_report(training_rows, training_anomalies)
    else:
        report["training"] = {"status": "not_connected", "anomalies": []}

    effect_rows: list[dict[str, Any]] = []
    if effect_log:
        effect_rows, effect_anomalies = read_effect_log(effect_log)
        report["knowledge_effect"] = effect_report(effect_rows, effect_anomalies, baseline_variant=baseline_variant)
    else:
        report["knowledge_effect"] = {"status": "not_connected", "anomalies": []}

    if baseline_report:
        try:
            baseline = json.loads(Path(baseline_report).read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ValueError("Baseline report is not valid JSON") from exc
        report["drift"] = drift_report(metadata, baseline, drift_threshold)
    else:
        report["drift"] = {"status": "not_connected", "anomalies": []}

    all_anomalies = [
        {"scope": scope, **item}
        for scope, items in (
            ("metadata", metadata["anomalies"]),
            ("dataset", report["dataset"].get("anomalies", [])),
            ("training", report["training"].get("anomalies", [])),
            ("knowledge_effect", report["knowledge_effect"].get("anomalies", [])),
            ("drift", report["drift"].get("anomalies", [])),
        )
        for item in items
    ]
    report["overview"] = {
        "anomalies": len(all_anomalies),
        "anomalies_by_scope": dict(Counter(item["scope"] for item in all_anomalies)),
        "connected_inputs": {
            "canonical_records": True, "dataset_manifest": bool(dataset_manifest),
            "training_log": bool(training_log), "effect_log": bool(effect_log),
            "baseline_report": bool(baseline_report),
        },
    }

    _write_csv(output_path / "records.csv", ["vuln_id", "status", "missing_fields", "conflicted_fields"], (
        {
            "vuln_id": record.get("vuln_id"), "status": record.get("status"),
            "missing_fields": [key for key, value in record.get("field_states", {}).items() if value == "missing"],
            "conflicted_fields": sorted(record.get("conflicts", {})),
        }
        for record in records
    ))
    _write_csv(output_path / "anomalies.csv", ["scope", "kind", "line", "run_id", "sample_id", "vuln_id", "fields", "details"], (
        {**item, "details": {key: value for key, value in item.items() if key not in {"scope", "kind", "line", "run_id", "sample_id", "vuln_id", "fields"}}}
        for item in all_anomalies
    ))
    if dataset_rows:
        _write_csv(output_path / "dataset-manifest.csv", ["line", "sample_id", "vuln_id", "family_id", "split", "labels", "modalities", "weight"], dataset_rows)
    if training_rows:
        _write_csv(output_path / "training.csv", ["file", "line", "run_id", "step", *TRAINING_METRICS,
                                                          "dataset_version", "model_version", "timestamp", "status", "exit_reason"], training_rows)
    if effect_rows:
        _write_csv(output_path / "knowledge-effects.csv", ["line", "variant", "task", "metric", "direction", "seed", "dataset_version", "value"], effect_rows)
    if report["drift"].get("details"):
        _write_csv(output_path / "drift.csv", ["dimension", "category", "baseline_share", "current_share", "share_delta"], report["drift"]["details"])
    report["artifacts"] = ["quality.json", "records.csv", "anomalies.csv"]
    report["artifacts"] += [name for connected, name in (
        (dataset_rows, "dataset-manifest.csv"), (training_rows, "training.csv"), (effect_rows, "knowledge-effects.csv")
    ) if connected]
    if report["drift"].get("details"):
        report["artifacts"].append("drift.csv")
    if charts:
        report["artifacts"] += _write_charts(output_path, report, training_rows, report["knowledge_effect"] if effect_log else None)
    (output_path / "quality.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return report
