from types import SimpleNamespace
import sys

from scripts.build_public_catalog_exchange import parse_avd_catalog, parse_cnnvd_report


def test_parse_avd_public_catalog_row():
    html = """
    <table><tr>
      <td><a href="/detail?id=AVD-2024-3096">AVD-2024-3096</a></td>
      <td>XZ Utils backdoor</td><td>CVE-2024-3094 / CWE-506</td><td>2024-03-29</td>
    </tr></table>
    """
    records = parse_avd_catalog(
        html,
        "https://avd.aliyun.com/product?prod=xz&page=1",
        "a" * 64,
    )
    assert records[0]["source_id"] == "AVD-2024-3096"
    assert records[0]["aliases"] == ["CVE-2024-3094"]
    assert records[0]["fields"]["weaknesses"] == ["CWE-506"]
    assert records[0]["provenance"]["catalog_page_sha256"] == "a" * 64


def test_parse_cnnvd_official_report(monkeypatch, tmp_path):
    text = """1 AI component remote code execution
CNNVD-202601-1884
CVE-2024-58339 高危
"""
    fake_reader = lambda _path: SimpleNamespace(
        pages=[SimpleNamespace(extract_text=lambda: text)]
    )
    monkeypatch.setitem(sys.modules, "pypdf", SimpleNamespace(PdfReader=fake_reader))
    pdf_path = tmp_path / "report.pdf"
    pdf_path.write_bytes(b"official report fixture")

    records = parse_cnnvd_report(
        pdf_path,
        "https://www.cnnvd.org.cn/group1/M00/report.pdf",
    )
    assert records[0]["source_id"] == "CNNVD-202601-1884"
    assert records[0]["aliases"] == ["CVE-2024-58339"]
    assert records[0]["fields"]["severity"] == "high"
    assert records[0]["fields"]["title"] == "AI component remote code execution"
    assert records[0]["provenance"]["page"] == 1
