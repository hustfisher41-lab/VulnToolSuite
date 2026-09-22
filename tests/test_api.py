import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from vulntools.api import create_app
from vulntools.demo import demo_sources
from vulntools.embedding import HashEncoder, index_records
from vulntools.processing import duplicate_candidates, process
from vulntools.storage import Store


def test_local_api_shares_index_and_preserves_filters(tmp_path):
    path = tmp_path / "api.sqlite"
    with Store(path) as store:
        store.save_sources(demo_sources())
        store.replace_canonical(process(store.sources()))
        index_records(store, HashEncoder())
    client = TestClient(create_app(path))
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "漏洞知识与安全测试平台" in dashboard.text
    assert client.get("/health").json()["records"] == 3
    page = client.get("/records", params={"limit": 2, "offset": 1}).json()
    assert page["total"] == 3 and len(page["items"]) == 2
    assert client.get("/records/CVE-2099-1001").status_code == 200
    assert client.get("/records/AVD-DEMO-1001").status_code == 200
    assert client.get("/records/unknown").status_code == 404
    summary = client.get("/analytics/summary").json()
    assert summary["database"]["records"] == 3
    assert summary["index"]["ready"] is True
    assert summary["sandbox"]["execution_ready"] is False
    assert summary["trajectories"]["total"] == 0
    assert client.get("/trajectories").json() == {"total": 0, "items": []}
    assert client.get("/trajectories/missing").status_code == 404
    assert client.post("/search", json={"query": "archive", "severity": "critical"}).json() == {"hits": []}
    assert client.post("/search", json={"query": "archive", "top_k": 0}).status_code == 422
    response = client.post("/search", json={"query": "archive path"})
    assert response.status_code == 200
    assert response.json()["hits"][0]["vuln_id"] == "CVE-2099-1001"
    assert response.json()["hits"][0]["score_breakdown"]["query"]["best_view"]
    status = client.get("/index/status")
    assert status.status_code == 200 and status.json()["ready"] is True
    collection = client.get("/collection/status")
    assert collection.status_code == 200 and collection.json()["source_records"]["cve"] == 1
    similarity = client.post("/similarity", json={"left": "CVE-2099-1001", "right": "CVE-2099-1001"})
    assert similarity.status_code == 200
    assert similarity.json()["aggregate_similarity"] == pytest.approx(1)
    assert client.post("/similarity", json={"left": "missing", "right": "CVE-2099-1001"}).status_code == 422
    quality = client.get("/analytics/quality").json()
    assert quality["active"] == 3
    drift = client.post("/analytics/drift", json={"baseline": quality, "threshold": 0.1})
    assert drift.status_code == 200 and drift.json()["status"] == "stable"
    assert client.get("/analytics/alignment").json()["aligned"] is True
    assert client.post("/classify", json={"text": "unescaped HTML script", "top_k": 2}).status_code == 200
    clustered = client.post("/clusters", json={"clusters": 2})
    assert clustered.status_code == 200
    assert clustered.json()["records"] == 3


def test_similar_records_only_create_review_candidates():
    records = process(demo_sources())
    records[1]["fields"]["description"] = records[0]["fields"]["description"]
    candidates = duplicate_candidates(records)
    assert candidates[0]["decision"] == "needs_review"
    assert candidates[0]["score"] == 1
    assert len(records) == 3
