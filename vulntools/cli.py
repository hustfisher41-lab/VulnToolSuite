"""Small explicit CLI: no background downloads or automatic model API calls."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import ssl
import sys
from typing import Any

from .analytics import write_report
from .collection import collect_batch, collection_status, fetch_record, sync_cve_delta, sync_cve_directory, sync_nvd
from .closure import run_simple_closure
from .collectors import read_file
from .demo import demo_sources
from .docker_trajectories import generate_docker_trajectories
from .embedding import (
    DomainAdapterEncoder, HashEncoder, LocalSentenceEncoder, classify_text, cluster_records,
    fit_domain_adapter, generate_training_pairs, index_records, read_training_pairs,
)
from .enrichment import attach_ocr_artifact, attach_vision_artifact, enrich_missing
from .processing import alignment_report, duplicate_candidates, enrichment_plan, ocr_image, process, static_python_features
from .poc import import_poc_directory
from .reproduction import candidate_plan, smoke_workflow
from .sandbox import HttpsVMBackend, SandboxPolicy, analyze_events, preflight, run_in_vm
from .sandbox_deployment import build_node_bundle, node_check
from .search import evaluate as evaluate_search
from .search import index_status, record_similarity, search
from .storage import Store
from .training import build_training_dataset
from .trajectories import (
    export_category_databases, export_trajectories, import_trajectories, trajectory_from_smoke,
)
from .vision import LocalVisionEncoder, encode_image_artifact


def dump(data: Any, path: str | Path | None = None) -> None:
    text = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)
    if path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def make_encoder(args: Any):
    base = LocalSentenceEncoder(args.model_path) if getattr(args, "model_path", None) else HashEncoder(args.dimension)
    return DomainAdapterEncoder.load(base, args.adapter_path) if getattr(args, "adapter_path", None) else base


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="VulnToolSuite — offline evidence and retrieval tools")
    root.add_argument("--db", default="output/vulntools.sqlite", help="SQLite path (place before command)")
    commands = root.add_subparsers(dest="command", required=True)
    ingest = commands.add_parser("import", help="Import local CVE/NVD or AVD/CNNVD exchange JSON/JSONL")
    ingest.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"], required=True)
    ingest.add_argument("--input", required=True)
    collect = commands.add_parser("collect", help="Explicit network fetch for one source identifier")
    collect.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"], required=True)
    identity = collect.add_mutually_exclusive_group(required=True)
    identity.add_argument("--cve", help="Compatibility alias for --id")
    identity.add_argument("--id", help="CVE, AVD or CNNVD identifier")
    collect.add_argument("--url-template", help="HTTPS public-page template containing {id}")
    collect.add_argument("--api-config", help="Authorized AVD/CNNVD JSON API config; credentials come from its token_env")
    sync = commands.add_parser("sync", help="Resumable CVE delta or paginated NVD synchronization")
    sync.add_argument("--source", choices=["cve", "nvd"], required=True)
    sync.add_argument("--since", help="ISO-8601 lower bound; defaults to checkpoint or last 24 hours")
    sync.add_argument("--until", help="ISO-8601 upper bound for NVD; defaults to now")
    sync.add_argument("--full", action="store_true", help="Enumerate the full NVD API; not valid for CVE delta")
    sync.add_argument("--baseline-dir", help="Official cvelistV5 checkout/extracted release for CVE --full")
    sync.add_argument("--page-size", type=int, default=2000)
    sync.add_argument("--max-records", type=int)
    batch = commands.add_parser("collect-batch", help="Collect identifiers from a UTF-8 text or JSON file; continue on item errors")
    batch.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"], required=True)
    batch.add_argument("--input", required=True)
    batch.add_argument("--url-template", help="HTTPS public-page template containing {id}")
    batch.add_argument("--api-config", help="Authorized AVD/CNNVD JSON API config")
    retry = commands.add_parser("retry-collection", help="Retry unresolved collection failures")
    retry.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"])
    retry.add_argument("--url-template", help="HTTPS public-page template containing {id}")
    retry.add_argument("--api-config", help="Authorized AVD/CNNVD JSON API config; requires --source")
    commands.add_parser("collection-status", help="Show source counts, sync cursors, and unresolved failures")
    poc_import = commands.add_parser("import-poc", help="Statically import CVE-linked PoC artifacts; never execute them")
    poc_import.add_argument("--source", choices=["nuclei", "exploitdb"], required=True)
    poc_import.add_argument("--input", required=True, help="Extracted official source directory")
    poc_import.add_argument("--commit-ref", help="Pinned upstream commit used for provenance")
    poc_import.add_argument("--license", dest="license_name", help="License asserted by the upstream snapshot")
    poc_import.add_argument("--max-files", type=int)
    poc_status = commands.add_parser("poc-status", help="Report PoC artifacts, versions, CVE coverage and review states")
    poc_status.add_argument("--output", help="Optional JSON report path")
    normalize = commands.add_parser("process", help="Merge current source facts and discover missing fields")
    normalize.add_argument("--output", default="output/canonical.json")
    normalize.add_argument("--plan", default="output/enrichment-plan.json")
    normalize.add_argument("--alignment", default="output/alignment.json")
    enrich = commands.add_parser("enrich", help="Fetch evidence for missing fields and reprocess canonical records")
    enrich.add_argument("--sources", nargs="+", choices=["cve", "nvd", "avd", "cnnvd"], default=["cve", "nvd"])
    enrich.add_argument("--max-records", type=int, default=100)
    enrich.add_argument("--max-requests", type=int, default=200)
    enrich.add_argument("--avd-url-template", help="HTTPS page template containing {id}")
    enrich.add_argument("--cnnvd-url-template", help="HTTPS page template containing {id}")
    enrich.add_argument("--avd-api-config", help="Authorized AVD JSON API config")
    enrich.add_argument("--cnnvd-api-config", help="Authorized CNNVD JSON API config")
    enrich.add_argument("--dry-run", action="store_true", help="Fetch and compare without changing stored records")
    index = commands.add_parser("index", help="Incremental local vector indexing")
    query = commands.add_parser("search", help="Hybrid cosine/BM25 retrieval, with strict filters")
    status = commands.add_parser("index-status", help="Check index coverage for the selected model")
    similarity = commands.add_parser("similarity", help="Compare two indexed vulnerabilities by view")
    evaluation = commands.add_parser("evaluate-search", help="Evaluate retrieval against JSON or JSONL relevance judgments")
    for command in (index, query, status, similarity, evaluation):
        command.add_argument("--model-path", help="Existing local SentenceTransformer model; no downloads")
        command.add_argument("--adapter-path", help="Trained domain adapter JSON for the selected base model")
        command.add_argument("--dimension", type=int, default=512, help="Feature baseline dimension")
    index.add_argument("--batch-size", type=int, default=32, help="Document views encoded per model batch")
    index.add_argument("--max-records", type=int, help="Index at most this many missing/changed records")
    query.add_argument("--query", default="")
    query.add_argument("--poc-file", help="Read code as text; never execute it")
    query.add_argument("--component")
    query.add_argument("--version")
    query.add_argument("--cpe", dest="cpes", action="append", help="Complete target CPE 2.3 context; repeat for AND environments")
    query.add_argument("--severity")
    query.add_argument("--weakness")
    query.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"])
    query.add_argument("--top-k", type=int, default=10)
    query.add_argument("--offset", type=int, default=0)
    query.add_argument("--mode", choices=["hybrid", "dense", "sparse"], default="hybrid")
    query.add_argument("--min-similarity", type=float)
    similarity.add_argument("--left", required=True)
    similarity.add_argument("--right", required=True)
    similarity.add_argument("--views", nargs="*")
    evaluation.add_argument("--input", required=True, help="JSON array or JSONL with query and relevant IDs")
    evaluation.add_argument("--cutoffs", type=int, nargs="+", default=[1, 5, 10])
    pairs = commands.add_parser("embedding-pairs", help="Create cross-field positive and different-CWE negative pairs")
    pairs.add_argument("--output", default="output/embedding-pairs.jsonl")
    pairs.add_argument("--max-negative-pairs", type=int, default=10000)
    fit = commands.add_parser("fit-embedding", help="Train a domain metric adapter over a fixed local encoder")
    fit.add_argument("--pairs", required=True)
    fit.add_argument("--output-model", required=True)
    fit.add_argument("--model-path", help="Existing local SentenceTransformer model; no downloads")
    fit.add_argument("--dimension", type=int, default=512)
    fit.add_argument("--epochs", type=int, default=8)
    fit.add_argument("--learning-rate", type=float, default=0.2)
    fit.add_argument("--negative-margin", type=float, default=0.2)
    training_dataset = commands.add_parser(
        "build-training-dataset", help="Export grounded SFT/RAG and review-only preference candidates")
    training_dataset.add_argument("--output", default="output/training-dataset")
    training_dataset.add_argument("--max-records", type=int)
    training_dataset.add_argument("--min-description-chars", type=int, default=40)
    training_dataset.add_argument("--chunk-chars", type=int, default=4000)
    training_dataset.add_argument("--chunk-overlap", type=int, default=200)
    training_dataset.add_argument("--max-code-chars", type=int, default=200000)
    training_dataset.add_argument("--split-seed", default="vulntools-v1")
    training_dataset.add_argument("--no-code", action="store_true")
    clusters = commands.add_parser("cluster-embeddings", help="Cluster active vulnerability embeddings")
    clusters.add_argument("--clusters", type=int, default=8)
    clusters.add_argument("--output", default="output/embedding-clusters.json")
    clusters.add_argument("--model-path")
    clusters.add_argument("--adapter-path")
    clusters.add_argument("--dimension", type=int, default=512)
    classifier = commands.add_parser("classify-vulnerability", help="Rank weakness labels for supplied text")
    classifier_input = classifier.add_mutually_exclusive_group(required=True)
    classifier_input.add_argument("--text")
    classifier_input.add_argument("--input", help="UTF-8 text or code file")
    classifier.add_argument("--top-k", type=int, default=5)
    classifier.add_argument("--model-path")
    classifier.add_argument("--adapter-path")
    classifier.add_argument("--dimension", type=int, default=512)
    report = commands.add_parser("analyze", help="Dataset, training and knowledge-injection analytics")
    report.add_argument("--output", default="output/analysis")
    report.add_argument("--dataset-manifest", help="JSONL sample/split/label manifest")
    report.add_argument("--training-log", help="JSONL training metrics file or append-only JSONL directory")
    report.add_argument("--effect-log", help="JSONL repeated baseline and injection evaluation metrics")
    report.add_argument("--baseline-report", help="Previous quality.json used for distribution and coverage drift")
    report.add_argument("--baseline-variant", default="baseline")
    report.add_argument("--rare-share", type=float, default=0.05, help="Flag labels below this assignment share")
    report.add_argument("--drift-threshold", type=float, default=0.10, help="Jensen-Shannon/coverage drift alert threshold")
    report.add_argument("--charts", action="store_true")
    demo = commands.add_parser("demo", help="Run the entire offline pipeline on explicitly synthetic data")
    demo.add_argument("--output", default="output/demo")
    demo.add_argument("--charts", action="store_true")
    ocr = commands.add_parser("ocr", help="Optional local Tesseract image extraction")
    ocr.add_argument("--input", required=True)
    ocr.add_argument("--language", default="eng")
    ocr.add_argument("--output", required=True)
    attach_ocr = commands.add_parser("attach-ocr", help="Attach a reviewed OCR artifact to one source record")
    attach_ocr.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"], required=True)
    attach_ocr.add_argument("--id", required=True)
    attach_ocr.add_argument("--artifact", required=True)
    attach_ocr.add_argument("--replace-existing", action="store_true")
    vision = commands.add_parser("vision-encode", help="Encode image pixels with an existing local vision model")
    vision.add_argument("--input", required=True)
    vision.add_argument("--model-path", required=True, help="Existing local native-image SentenceTransformer model")
    vision.add_argument("--output", required=True)
    attach_vision = commands.add_parser("attach-vision", help="Attach a native-image embedding artifact to one source record")
    attach_vision.add_argument("--source", choices=["cve", "nvd", "avd", "cnnvd"], required=True)
    attach_vision.add_argument("--id", required=True)
    attach_vision.add_argument("--artifact", required=True)
    code = commands.add_parser("code-features", help="Python AST features; static parsing only")
    code.add_argument("--input", required=True)
    policy = commands.add_parser("sandbox-check", help="Validate policy, not isolation or execution readiness")
    policy.add_argument("--policy", required=True)
    sandbox_run = commands.add_parser("sandbox-run", help="Submit a sample to an attested disposable-VM backend")
    sandbox_run.add_argument("--policy", required=True)
    sandbox_run.add_argument("--sample", required=True)
    sandbox_run.add_argument("--output", required=True)
    sandbox_run.add_argument("--backend-url", required=True)
    sandbox_run.add_argument("--ca-file", required=True)
    sandbox_run.add_argument("--cert-file", required=True)
    sandbox_run.add_argument("--key-file", required=True)
    sandbox_run.add_argument("--token-env", required=True, help="Environment variable containing the backend bearer token")
    sandbox_run.add_argument("--attestation-key-env", required=True,
                             help="Environment variable containing the trusted backend attestation key")
    agent = commands.add_parser("sandbox-agent", help="Run the mTLS control API on a dedicated execution node")
    agent.add_argument("--config", required=True)
    agent.add_argument("--host", default="127.0.0.1")
    agent.add_argument("--port", type=int, default=9443)
    agent.add_argument("--ca-file", required=True)
    agent.add_argument("--cert-file", required=True)
    agent.add_argument("--key-file", required=True)
    acceptance = commands.add_parser("sandbox-acceptance", help="Run and sign harmless VM isolation acceptance checks")
    acceptance.add_argument("--config", required=True)
    acceptance.add_argument("--output", required=True)
    doctor = commands.add_parser("sandbox-node-check", help="Read-only diagnostics; never create a VM or execute samples")
    doctor.add_argument("--config")
    doctor.add_argument("--dedicated-node", action="store_true", help="Administrator confirms a dedicated execution host")
    doctor.add_argument("--output")
    bundle = commands.add_parser("sandbox-node-bundle", help="Export secret-free offline assets; does not install or enable anything")
    bundle.add_argument("--output", required=True)
    monitor = commands.add_parser("sandbox-guest-monitor", help="Linux guest ONLY; built-in harmless canaries only")
    monitor.add_argument("--port", type=int, default=4050)
    events = commands.add_parser("sandbox-events", help="Analyze supplied syscall logs without executing samples")
    events.add_argument("--input", required=True)
    candidates = commands.add_parser("reproduction-candidates", help="Read-only PoC shortlist; no code execution")
    candidates.add_argument("--limit", type=int, default=3)
    candidates.add_argument("--output", required=True)
    smoke = commands.add_parser("reproduction-smoke", help="Harmless paired canary: plan, fixture or attested VM")
    smoke.add_argument("--mode", choices=["plan", "fixture", "vm"], default="plan")
    smoke.add_argument("--output", required=True)
    smoke.add_argument("--policy")
    for flag in ("backend-url", "ca-file", "cert-file", "key-file", "token-env", "attestation-key-env",
                 "image-sha256", "kernel-sha256", "supervisor-sha256"):
        smoke.add_argument("--" + flag)
    trajectory_smoke = commands.add_parser(
        "trajectory-smoke", help="Run the harmless fixture canary and persist an explicitly simulated trajectory")
    trajectory_smoke.add_argument("--output", default="output/trajectory-smoke")
    trajectory_import = commands.add_parser(
        "trajectory-import", help="Import authorized structured security trajectories from JSON/JSONL")
    trajectory_import.add_argument("--input", required=True)
    trajectory_export = commands.add_parser(
        "trajectory-export", help="Export trajectories plus observable-action SFT JSONL")
    trajectory_export.add_argument("--output", default="output/security-trajectories")
    trajectory_docker = commands.add_parser(
        "trajectory-docker-generate",
        help="Execute harmless canaries in a restricted local Docker container and persist structured trajectories",
    )
    trajectory_docker.add_argument("--output", default="output/docker-trajectories")
    trajectory_docker.add_argument("--count", type=int, default=1500)
    trajectory_docker.add_argument("--seed", default="vulntools-docker-lab-v1")
    trajectory_docker.add_argument("--image", default="python:3.12", help="Existing local image; automatic pulls are disabled")
    trajectory_docker.add_argument("--timeout", type=int, default=300)
    trajectory_split = commands.add_parser(
        "trajectory-split-databases",
        help="Export Docker trajectories into separate technical and business-logic SQLite databases",
    )
    trajectory_split.add_argument("--output", default="output/docker-trajectory-databases")
    trajectory_split.add_argument("--expected-per-category", type=int)
    trajectory_split.add_argument("--overwrite", action="store_true")
    commands.add_parser("trajectory-status", help="Show real/simulated trajectory and runtime-event counts")
    closure = commands.add_parser(
        "simple-closure", help="Run the usable local data/search/dataset/fixture-trajectory acceptance loop")
    closure.add_argument("--output", default="output/simple-closure")
    closure.add_argument("--query", default="CVE-1999-0001 BSD crafted packets")
    closure.add_argument("--expected-id")
    closure.add_argument("--model-path")
    closure.add_argument("--adapter-path")
    closure.add_argument("--dimension", type=int, default=512)
    commands.add_parser("jobs", help="List local command execution history")
    duplicates = commands.add_parser("duplicates", help="Find lexical duplicate candidates; never auto-merge")
    duplicates.add_argument("--threshold", type=float, default=0.65)
    server = commands.add_parser("serve", help="Optional read-only HTTP API on 127.0.0.1")
    server.add_argument("--port", type=int, default=8765)
    server.add_argument("--model-path")
    server.add_argument("--adapter-path")
    server.add_argument("--dimension", type=int, default=512)
    return root


def main(argv: list[str] | None = None) -> int:
    # Stable UTF-8 JSON when redirected from Windows terminals or API tooling.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    args = parser().parse_args(argv)
    try:
        if args.command == "serve":
            from .api import create_app
            try:
                import uvicorn
            except ImportError as exc:
                raise RuntimeError("Install the api extra to run the HTTP interface") from exc
            uvicorn.run(create_app(args.db, args.model_path, args.dimension, args.adapter_path), host="127.0.0.1", port=args.port)
            return 0
        if args.command == "sandbox-agent":
            from .sandbox_agent import create_sandbox_agent_app, load_agent_config
            try:
                import uvicorn
            except ImportError as exc:
                raise RuntimeError("Install the api extra to run sandbox-agent") from exc
            config = load_agent_config(args.config)
            uvicorn.run(
                create_sandbox_agent_app(config), host=args.host, port=args.port,
                ssl_ca_certs=args.ca_file, ssl_certfile=args.cert_file, ssl_keyfile=args.key_file,
                ssl_cert_reqs=ssl.CERT_REQUIRED,
            )
            return 0
        if args.command == "sandbox-acceptance":
            from .sandbox_agent import load_agent_config, write_acceptance_record
            config = load_agent_config(args.config, require_acceptance=False)
            dump(write_acceptance_record(config, args.output))
            return 0
        if args.command == "sandbox-node-check":
            report = node_check(args.config, dedicated_node=args.dedicated_node)
            if args.output:
                dump(report, args.output)
            dump(report)
            return 0 if report["mechanical_checks_passed"] else 2
        if args.command == "sandbox-node-bundle":
            dump(build_node_bundle(args.output))
            return 0
        if args.command == "sandbox-guest-monitor":
            from .guest_monitor import serve_one_guest
            dump(serve_one_guest(args.port))
            return 0
        if args.command == "sandbox-check":
            report = preflight(SandboxPolicy.load(args.policy))
            dump(report)
            return 0 if report["policy_valid"] else 2
        if args.command == "sandbox-run":
            token = os.getenv(args.token_env)
            attestation_key = os.getenv(args.attestation_key_env)
            if not token or not attestation_key:
                raise ValueError("Sandbox token and attestation key environment variables must both be set")
            backend = HttpsVMBackend(
                args.backend_url, args.ca_file, args.cert_file, args.key_file,
                token, attestation_key.encode("utf-8"),
            )
            report = run_in_vm(args.sample, args.output, SandboxPolicy.load(args.policy), backend)
            dump(report, Path(args.output) / "run-report.json")
            dump(report)
            return 0
        if args.command == "sandbox-events":
            dump(analyze_events(args.input))
            return 0
        if args.command == "reproduction-candidates":
            report = candidate_plan(args.db, limit=args.limit)
            dump(report, args.output)
            dump(report)
            return 0
        if args.command == "reproduction-smoke":
            backend, pins = None, None
            connection_fields = ("backend_url", "ca_file", "cert_file", "key_file", "token_env", "attestation_key_env")
            pin_fields = ("image_sha256", "kernel_sha256", "supervisor_sha256")
            if args.mode == "vm":
                if not all(getattr(args, name) for name in (*connection_fields, *pin_fields)):
                    raise ValueError("vm mode requires mTLS backend configuration and image/kernel/supervisor pins")
                token, key = os.getenv(args.token_env), os.getenv(args.attestation_key_env)
                if not token or not key:
                    raise ValueError("Sandbox token and attestation key environment variables must both be set")
                backend = HttpsVMBackend(args.backend_url, args.ca_file, args.cert_file, args.key_file,
                                        token, key.encode("utf-8"))
                pins = {name: getattr(args, name) for name in pin_fields}
            elif any(getattr(args, name) for name in (*connection_fields, *pin_fields)):
                raise ValueError("VM connection parameters must not be supplied in plan or fixture mode")
            report = smoke_workflow(args.output, mode=args.mode, backend=backend, pins=pins,
                                    policy=SandboxPolicy.load(args.policy) if args.policy else SandboxPolicy())
            dump(report)
            return 0 if report["status"] in {"planned", "fixture_passed", "canary_passed"} else 2
        if args.command == "ocr":
            dump(ocr_image(args.input, args.language), args.output)
            return 0
        if args.command == "vision-encode":
            dump(encode_image_artifact(args.input, LocalVisionEncoder(args.model_path)), args.output)
            return 0
        if args.command == "code-features":
            dump(static_python_features(Path(args.input).read_text(encoding="utf-8")))
            return 0
        with Store(args.db) as store:
            job_id = store.start_job(args.command)
            try:
                if args.command == "import":
                    records = read_file(args.source, args.input)
                    report = store.save_sources_detailed(records)
                elif args.command == "collect":
                    identifier = args.id or args.cve
                    record = fetch_record(args.source, identifier, api_key=os.getenv("NVD_API_KEY"),
                                          url_template=args.url_template, authorized_config=args.api_config)
                    report = store.save_sources_detailed([record])
                    report.update({"source": args.source, "id": record.source_id})
                elif args.command == "sync":
                    if args.source == "cve":
                        if args.until:
                            raise ValueError("CVE sync does not accept --until")
                        if args.full:
                            if not args.baseline_dir or args.since:
                                raise ValueError("CVE --full requires --baseline-dir and does not accept --since")
                            report = sync_cve_directory(store, args.baseline_dir, batch_size=args.page_size,
                                                        max_records=args.max_records)
                        else:
                            if args.baseline_dir:
                                raise ValueError("--baseline-dir requires CVE --full")
                            report = sync_cve_delta(store, since=args.since, max_records=args.max_records)
                    else:
                        if args.baseline_dir:
                            raise ValueError("--baseline-dir only applies to CVE --full")
                        report = sync_nvd(store, since=args.since, until=args.until, full=args.full,
                                          page_size=args.page_size, max_records=args.max_records,
                                          api_key=os.getenv("NVD_API_KEY"))
                elif args.command in {"collect-batch", "retry-collection"}:
                    if args.command == "collect-batch":
                        content = Path(args.input).read_text(encoding="utf-8-sig")
                        try:
                            value = json.loads(content)
                            identifiers = value if isinstance(value, list) else value.get("ids", [])
                        except json.JSONDecodeError:
                            identifiers = [line.strip() for line in content.splitlines() if line.strip()]
                        if not isinstance(identifiers, list) or any(not isinstance(item, str) for item in identifiers):
                            raise ValueError("Batch input must be a JSON string array, {ids:[...]}, or one identifier per line")
                        source = args.source
                    else:
                        if args.api_config and not args.source:
                            raise ValueError("retry-collection --api-config requires --source")
                        all_failures = [item for item in store.collection_failures() if not args.source or item["source"] == args.source]
                        failures = [item for item in all_failures if not item["item_id"].startswith("file:")]
                        grouped = {}
                        for item in failures:
                            grouped.setdefault(item["source"], []).append(item["item_id"])
                        reports = [collect_batch(store, source, ids, api_key=os.getenv("NVD_API_KEY"),
                                                 url_template=args.url_template,
                                                 authorized_config=args.api_config) for source, ids in grouped.items()]
                        report = {"sources": reports, "baseline_file_failures_skipped": len(all_failures) - len(failures),
                                  "remaining_failures": len(store.collection_failures())}
                        identifiers = None
                        source = None
                    if identifiers is not None:
                        report = collect_batch(store, source, identifiers, api_key=os.getenv("NVD_API_KEY"),
                                               url_template=args.url_template, authorized_config=args.api_config)
                elif args.command == "collection-status":
                    report = collection_status(store)
                elif args.command == "import-poc":
                    report = import_poc_directory(
                        store, args.source, args.input, commit_ref=args.commit_ref,
                        license_name=args.license_name, max_files=args.max_files,
                    )
                elif args.command == "poc-status":
                    report = store.poc_status()
                    if args.output:
                        dump(report, args.output)
                elif args.command == "process":
                    records = process(store.sources())
                    store.replace_canonical(records)
                    dump(records, args.output)
                    dump(enrichment_plan(records), args.plan)
                    dump(alignment_report(records), args.alignment)
                    report = {"records": len(records), "output": args.output, "enrichment_plan": args.plan, "alignment": args.alignment}
                elif args.command == "enrich":
                    report = enrich_missing(
                        store, sources=args.sources, api_key=os.getenv("NVD_API_KEY"),
                        url_templates={"avd": args.avd_url_template, "cnnvd": args.cnnvd_url_template},
                        authorized_configs={key: value for key, value in {
                            "avd": args.avd_api_config, "cnnvd": args.cnnvd_api_config}.items() if value},
                        max_records=args.max_records, max_requests=args.max_requests, apply=not args.dry_run,
                    )
                elif args.command == "attach-ocr":
                    report = attach_ocr_artifact(store, args.source, args.id, args.artifact, replace_existing=args.replace_existing)
                elif args.command == "attach-vision":
                    report = attach_vision_artifact(store, args.source, args.id, args.artifact)
                elif args.command == "embedding-pairs":
                    pairs = generate_training_pairs(store.records(), args.max_negative_pairs)
                    target = Path(args.output)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text("".join(json.dumps(item, ensure_ascii=False, allow_nan=False) + "\n" for item in pairs), encoding="utf-8")
                    report = {"output": str(target.resolve()), "pairs": len(pairs),
                              "positive": sum(item["label"] == 1 for item in pairs), "negative": sum(item["label"] == 0 for item in pairs)}
                elif args.command == "fit-embedding":
                    base = LocalSentenceEncoder(args.model_path) if args.model_path else HashEncoder(args.dimension)
                    report = fit_domain_adapter(base, read_training_pairs(args.pairs), args.output_model,
                                                epochs=args.epochs, learning_rate=args.learning_rate,
                                                negative_margin=args.negative_margin)
                elif args.command == "build-training-dataset":
                    report = build_training_dataset(
                        store, args.output, max_records=args.max_records,
                        min_description_chars=args.min_description_chars,
                        chunk_chars=args.chunk_chars, chunk_overlap=args.chunk_overlap,
                        max_code_chars=args.max_code_chars, split_seed=args.split_seed,
                        include_code=not args.no_code,
                    )
                elif args.command == "trajectory-smoke":
                    workflow = smoke_workflow(args.output, mode="fixture", policy=SandboxPolicy())
                    trajectory = trajectory_from_smoke(workflow)
                    saved = store.save_trajectory(trajectory)
                    exported = export_trajectories(store, Path(args.output) / "dataset")
                    report = {"workflow_status": workflow["status"], "is_simulated": True,
                              "trajectory": saved, "dataset": exported,
                              "note": "Fixture closure only; this is not real isolation or real-vulnerability proof."}
                elif args.command == "trajectory-import":
                    report = import_trajectories(store, args.input)
                elif args.command == "trajectory-export":
                    report = export_trajectories(store, args.output)
                elif args.command == "trajectory-docker-generate":
                    report = generate_docker_trajectories(
                        store,
                        args.output,
                        count=args.count,
                        seed=args.seed,
                        image=args.image,
                        timeout=args.timeout,
                    )
                elif args.command == "trajectory-split-databases":
                    report = export_category_databases(
                        store,
                        args.output,
                        expected_per_category=args.expected_per_category,
                        overwrite=args.overwrite,
                    )
                elif args.command == "trajectory-status":
                    report = store.trajectory_summary()
                elif args.command == "simple-closure":
                    report = run_simple_closure(
                        store, args.db, args.output, make_encoder(args), query=args.query,
                        expected_id=args.expected_id,
                    )
                elif args.command == "cluster-embeddings":
                    report = cluster_records(store.records(), make_encoder(args), args.clusters)
                    dump(report, args.output)
                elif args.command == "classify-vulnerability":
                    text_input = args.text if args.text is not None else Path(args.input).read_text(encoding="utf-8-sig")
                    report = {"predictions": classify_text(store.records(), make_encoder(args), text_input, args.top_k)}
                elif args.command in {"index", "search", "index-status", "similarity", "evaluate-search"}:
                    encoder = make_encoder(args)
                    if args.command == "index":
                        report = index_records(
                            store, encoder, batch_size=args.batch_size, max_records=args.max_records,
                        )
                    elif args.command == "search":
                        poc = Path(args.poc_file).read_text(encoding="utf-8") if args.poc_file else ""
                        report = {"hits": search(store, encoder, args.query, poc=poc, component=args.component,
                                                 version=args.version, severity=args.severity, weakness=args.weakness,
                                                 source=args.source, top_k=args.top_k, offset=args.offset,
                                                 mode=args.mode, min_similarity=args.min_similarity, cpes=args.cpes)}
                    elif args.command == "index-status":
                        report = index_status(store, encoder)
                    elif args.command == "similarity":
                        report = record_similarity(store, encoder, args.left, args.right, args.views)
                    else:
                        content = Path(args.input).read_text(encoding="utf-8-sig")
                        try:
                            parsed = json.loads(content)
                            cases = parsed if isinstance(parsed, list) else [parsed]
                        except json.JSONDecodeError:
                            cases = [json.loads(line) for line in content.splitlines() if line.strip()]
                        report = evaluate_search(store, encoder, cases, args.cutoffs)
                elif args.command == "analyze":
                    report = write_report(
                        store.records(), args.output,
                        dataset_manifest=args.dataset_manifest,
                        training_log=args.training_log,
                        effect_log=args.effect_log,
                        baseline_report=args.baseline_report,
                        baseline_variant=args.baseline_variant,
                        rare_share=args.rare_share,
                        drift_threshold=args.drift_threshold,
                        charts=args.charts,
                    )
                elif args.command == "demo":
                    count = store.save_sources(demo_sources())
                    records = process(store.sources())
                    store.replace_canonical(records)
                    output = Path(args.output)
                    dump(records, output / "canonical.json")
                    dump(enrichment_plan(records), output / "enrichment-plan.json")
                    dump(alignment_report(records), output / "alignment.json")
                    indexed = index_records(store, HashEncoder())
                    hits = search(store, HashEncoder(), "压缩包解压路径穿越 archive destination path")
                    dump(hits, output / "search.json")
                    quality = write_report(records, output / "analysis", charts=args.charts)
                    report = {"synthetic_data": True, "changed_sources": count, "records": len(records), "index": indexed,
                              "top_hit": hits[0]["vuln_id"] if hits else None, "output": str(output.resolve()), "quality": quality}
                elif args.command == "jobs":
                    report = {"jobs": [dict(row) for row in store.db.execute("SELECT * FROM jobs ORDER BY job_id DESC LIMIT 50")]}
                elif args.command == "duplicates":
                    report = {"candidates": duplicate_candidates(store.records(), args.threshold)}
                else:
                    raise ValueError("Unknown command")
                store.end_job(job_id, "succeeded", {"command": args.command})
                dump(report)
                return 0
            except Exception as exc:
                store.end_job(job_id, "failed", {"error": str(exc)})
                raise
    except (ValueError, KeyError, OSError, RuntimeError, TypeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
