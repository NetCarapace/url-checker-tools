"""Tests for download link detection in file scanning."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.services.file_scan_service import FileScanService


def yara_result(details):
    return ProviderResult(
        provider="yara",
        target="https://example.test",
        is_threat=False,
        threat_level=ThreatLevel.SAFE,
        confidence=0.9,
        details=details,
    )


def test_download_url_detection_ignores_query_string():
    service = FileScanService(logger=None)
    assert service._is_download_url("https://example.test/setup.EXE")
    assert service._is_download_url("https://example.test/file.zip?token=abc")
    assert not service._is_download_url("https://example.test/page.html")
    assert not service._is_download_url("https://example.test/?file=setup.exe")


def test_target_itself_is_detected_as_download():
    service = FileScanService(logger=None)
    target = "https://example.test/tool.msi"
    assert service._extract_download_urls(target, []) == [target]


def test_download_links_from_yara_results_without_duplicates():
    service = FileScanService(logger=None)
    links = ["https://example.test/a.apk", "https://example.test/a.apk"]
    urls = service._extract_download_urls(
        "https://example.test/", [yara_result({"download_links": links})]
    )
    assert urls == ["https://example.test/a.apk"]


def test_download_urls_from_yara_rule_matches():
    service = FileScanService(logger=None)
    matches = [
        {
            "rule": "Download_Detected",
            "strings": ["https://example.test/x.jar", "text"],
        },
        {"rule": "Phishing_Form", "strings": ["https://example.test/y.exe"]},
    ]
    urls = service._extract_download_urls(
        "https://example.test/", [yara_result({"matches": matches})]
    )
    assert urls == ["https://example.test/x.jar"]
