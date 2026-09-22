"""Entirely synthetic offline samples; identifiers do not assert real CVEs."""
from .collectors import parse
from .models import SourceRecord


def demo_sources() -> list[SourceRecord]:
    cve = {"cveMetadata": {"cveId": "CVE-2099-1001", "state": "PUBLISHED"}, "containers": {"cna": {
        "title": "DEMO: Archive extraction path traversal",
        "descriptions": [{"lang": "en", "value": "Synthetic example: an archive extractor does not validate the destination path before writing a file."},
                         {"lang": "zh", "value": "虚构演示：压缩包解压时未校验目标路径，可能导致路径穿越和越界文件写入。"}],
        "affected": [{"vendor": "DemoVendor", "product": "demo-archive", "defaultStatus": "unaffected", "versions": [{"version": "1.0.0", "lessThan": "1.2.0", "versionType": "semver", "status": "affected"}]}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-22"}]}],
        "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "version": "3.1"}}],
        "references": [{"url": "https://example.invalid/demo/archive"}]}}}
    records = parse("cve", cve)
    for source, source_id, fields in [
        ("avd", "AVD-DEMO-1001", {"patch": "Resolve the destination path, then verify it remains inside the extraction root before writing.", "attack_preconditions": "An application processes an untrusted archive."}),
        ("cnnvd", "CNNVD-DEMO-1001", {"severity": "medium", "image_text": "演示图片的人工转录：目标文件路径必须位于解压目录内。"}),
    ]:
        records.extend(parse(source, {"source_id": source_id, "aliases": ["CVE-2099-1001"], "url": f"https://example.invalid/{source}/{source_id}", "fields": fields}))
    for cve_id, desc, cwe in [("CVE-2099-1002", "Synthetic example: a web template reflects unescaped user input into HTML, causing cross-site scripting. 跨站脚本，输出未进行转义。", "CWE-79"),
                              ("CVE-2099-1003", "Synthetic example: a database query concatenates untrusted input instead of using parameter binding. SQL injection. SQL注入。", "CWE-89")]:
        records.extend(parse("nvd", {"cve": {"id": cve_id, "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": desc}],
                                              "weaknesses": [{"description": [{"value": cwe}]}],
                                              "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5, "version": "3.1"}}]}}}))
    return records
