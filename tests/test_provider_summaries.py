"""Characterization tests: the per-provider summary text in robot logs and the robot verbose summary."""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.cli.output_service import OutputService
from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.services.robot_log_service import RobotLogBuilder
from url_checker_tools.services.scan_request import ScanRequest

TARGET = "https://example.test/login"
LEVEL_IS_THREAT = {ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL, ThreatLevel.SUSPICIOUS}


def result(provider, level=ThreatLevel.SAFE, details=None, error=None):
    return ProviderResult(
        provider=provider,
        target=TARGET,
        is_threat=level in LEVEL_IS_THREAT,
        threat_level=level,
        confidence=0.9,
        details=details if details is not None else {},
        error_message=error,
    )


def synthesis(*results):
    return RobotLogBuilder("sid", None)._create_enhanced_synthesis_content(
        list(results), {}
    )


M, S, SUS = ThreatLevel.MALICIOUS, ThreatLevel.SAFE, ThreatLevel.SUSPICIOUS
ERR = ThreatLevel.ERROR

# (result, expected text in synthesis["providers"][provider])
SYNTHESIS_CASES = {
    "whois_age": (
        result("whois", S, {"domain_age_days": 9000, "registrar": "Example Reg"}),
        "Age: 9000 days; Registrar: Example Reg",
    ),
    "whois_no_registrar": (
        result("whois", S, {"domain_age_days": 12}),
        "Age: 12 days; Registrar: Unknown",
    ),
    "whois_unparsable_creation_date": (
        result("whois", S, {"domain_age_days": 0, "creation_date": "soon"}),
        "Age: 0 days; Registrar: Unknown",
    ),
    "whois_no_details": (result("whois", S), "Safe"),
    "virustotal_malicious_categories": (
        result(
            "virustotal",
            M,
            {
                "malicious_count": 5,
                "total_engines": 90,
                "categories": ["Phishing", "phishing", " Malware ", 7, ""],
            },
        ),
        "Malicious (5/90) | Categories: phishing, malware",
    ),
    "virustotal_clean": (
        result("virustotal", S, {"malicious_count": 0, "total_engines": 90}),
        "Harmless (90 clean engines)",
    ),
    "virustotal_categories_vt": (
        result(
            "virustotal",
            S,
            {"malicious_count": 0, "total_engines": 3, "categories_vt": ["news"]},
        ),
        "Harmless (3 clean engines) | Categories: news",
    ),
    "virustotal_no_details": (result("virustotal", M), "Malicious"),
    "whalebone_malicious": (
        result(
            "whalebone",
            M,
            {
                "threat_types": ["phishing", "malware"],
                "categories": ["news", "news", "adult"],
                "max_accuracy": 95,
            },
        ),
        "Malicious | Threats: phishing, malware (max 95%) | Categories: news, adult",
    ),
    "whalebone_suspicious": (
        result("whalebone", SUS, {"threat_types": ["spam"], "max_accuracy": 40}),
        "Suspicious | Threats: spam (max 40%)",
    ),
    "whalebone_clean_categories": (
        result("whalebone", S, {"categories": ["news"]}),
        "Clean | Categories: news",
    ),
    "whalebone_no_details": (result("whalebone", S), "Clean"),
    "misp_threat": (
        result("misp", M, {"events_found": 3}),
        "Threats Found (3 events)",
    ),
    "misp_threat_no_events": (result("misp", M, {"events_found": 0}), "Clean"),
    "misp_clean": (result("misp", S, {"events_found": 2}), "Clean"),
    "google_sb_threat": (result("google_sb", M), "Malicious"),
    "google_sb_safe": (result("google_sb", S), "Safe"),
    "link_analyzer_malicious": (
        result("link_analyzer", M, {"redirect_count": 2, "domain_changed": True}),
        "Malicious | 2 redirect(s) | domain change: yes",
    ),
    "link_analyzer_suspicious": (
        result("link_analyzer", SUS, {"redirect_count": 1}),
        "Suspicious | 1 redirect(s)",
    ),
    "link_analyzer_safe": (
        result("link_analyzer", S, {"redirect_count": 0}),
        "Safe | 0 redirect(s)",
    ),
    "link_analyzer_no_details": (result("link_analyzer", S), "Safe"),
    "yara_summary": (
        result("yara", M, {"scan_summary": "1 pattern matches found: EICAR"}),
        "1 pattern matches found: EICAR",
    ),
    "yara_no_summary": (result("yara", S, {"matches": []}), "No pattern matches"),
    "yara_no_details": (result("yara", M), "Malicious"),
    "abuseipdb_high_risk": (
        result("abuseipdb", M, {"abuse_confidence": 87, "report_count": 4}),
        "High Risk (87%)",
    ),
    "abuseipdb_high_risk_api_keys": (
        result("abuseipdb", M, {"abuseConfidencePercentage": 60}),
        "High Risk (60%)",
    ),
    "abuseipdb_threat_no_confidence": (
        result("abuseipdb", M, {"report_count": 2}),
        "Low Risk (2 reports)",
    ),
    "abuseipdb_low_risk_api_keys": (
        result("abuseipdb", S, {"abuse_confidence": 10, "totalReports": 3}),
        "Low Risk (3 reports)",
    ),
    "abuseipdb_no_details": (result("abuseipdb", S), "Safe"),
    "other_provider_threat": (result("urlscan", SUS), "Malicious"),
    "other_provider_safe": (result("lookyloo", S), "Safe"),
    "error": (result("virustotal", ERR, {"status": "error"}, "boom"), "Error"),
    "unavailable": (
        result("virustotal", ERR, {"status": "unavailable"}, "not available"),
        "Unavailable",
    ),
}


@pytest.mark.parametrize("case", SYNTHESIS_CASES)
def test_synthesis_provider_summary(case):
    provider_result, expected = SYNTHESIS_CASES[case]
    assert synthesis(provider_result)["providers"] == {
        provider_result.provider: expected
    }


def test_whois_age_computed_from_creation_date():
    created = "2020-01-01"
    expected_age = (
        datetime.now(timezone.utc) - datetime(2020, 1, 1, tzinfo=timezone.utc)
    ).days
    out = synthesis(result("whois", S, {"creation_date": created, "registrar": "R"}))
    assert out["providers"]["whois"] == f"Age: {expected_age} days; Registrar: R"
    assert out["whois"]["age"] == expected_age


def test_synthesis_sections_and_key_order():
    out = synthesis(
        result(
            "whois",
            S,
            {"domain_age_days": 30, "domain_name": "example.test", "status": "ok"},
        ),
        result(
            "link_analyzer",
            S,
            {
                "redirect_count": 1,
                "final_url": "https://example.test/",
                "resolved_ips": ["192.0.2.1"],
                "contains_shorteners": True,
                "is_blocked": False,
            },
        ),
        result("yara", M, {"scan_summary": "hit"}),
    )
    assert list(out) == [
        "whois",
        "providers",
        "metadata_analysis",
        "link_analysis",
        "yara",
        "result",
    ]
    assert out["whois"] == {
        "is_active": True,
        "age": 30,
        "domain": "example.test",
        "status": "ok",
    }
    assert out["link_analysis"] == {
        "redirects": 1,
        "domain_change": False,
        "is_blocked": False,
        "final_url": "https://example.test/",
        "dns_resolved": True,
        "security_downgrades": 0,
        "contains_shorteners": True,
        "suspicious_patterns": [],
    }
    assert out["yara"] == {
        "type": "threat",
        "redirects": 0,
        "url_shorteners": 0,
        "domain_change": None,
        "security_downgrades": 0,
        "download_links": 0,
        "flags": [],
    }
    assert list(out["providers"]) == ["whois", "link_analyzer", "yara"]


def test_synthesis_without_whois_link_or_yara_has_no_optional_sections():
    out = synthesis(result("google_sb", S))
    assert list(out) == ["whois", "providers", "metadata_analysis", "result"]
    assert out["whois"] == {}


# ---- Robot verbose summary (stdout) -------------------------------------


def make_request():
    return ScanRequest(
        target=TARGET,
        providers=(),
        session_id="sid",
        format="synthesis",
        raw=False,
        robot=True,
        verbose=True,
        log=True,
        score=True,
        score_detail=False,
        misp_report=False,
        auto_scan_files=False,
        download=False,
        workflow=None,
    )


HEADER = ["", "=" * 60, "HUMAN-READABLE SUMMARY", "=" * 60]

# (result, expected printed lines after the header)
VERBOSE_CASES = {
    "virustotal_malicious_categories": (
        result(
            "virustotal",
            M,
            {
                "malicious_count": 5,
                "total_engines": 90,
                "categories": ["Phishing", "phishing", " Malware "],
            },
        ),
        [
            "⚠ virustotal: malicious (5/90 vendors) (categories: phishing, malware)",
            "   └─ Threat Level: malicious",
        ],
    ),
    "virustotal_clean": (
        result("virustotal", S, {"malicious_count": 0, "total_engines": 90}),
        ["✓ virustotal: safe (90 clean vendors)"],
    ),
    "virustotal_no_engines": (
        result("virustotal", S, {"malicious_count": 0, "total_engines": 0}),
        ["✓ virustotal: safe"],
    ),
    "virustotal_categories_vt": (
        result("virustotal", S, {"total_engines": 2, "categories_vt": ["news"]}),
        ["✓ virustotal: safe (2 clean vendors) (categories: news)"],
    ),
    "whalebone_full": (
        result(
            "whalebone",
            M,
            {
                "threat_types": ["phishing", "malware", "phishing"],
                "max_accuracy": 95,
                "categories": ["news", "adult", "news"],
                "category_classification": {
                    "security": ["a", "a", "b"],
                    "policy": ["c"],
                    "safe": [],
                },
            },
        ),
        [
            "⚠ whalebone: threat detected (threats: malware, phishing (max 95%))"
            " (categories: adult, news) [classification: security:2; policy:1]",
            "   └─ Threat Level: malicious",
        ],
    ),
    "whalebone_accuracy_fallback": (
        result("whalebone", SUS, {"threat_types": ["spam"], "accuracy": 80}),
        [
            "⚠ whalebone: threat detected (threats: spam (max 80%))",
            "   └─ Threat Level: suspicious",
        ],
    ),
    "whalebone_clean": (
        result("whalebone", S, {"categories": ["news"]}),
        ["✓ whalebone: safe (categories: news)"],
    ),
    "misp_events": (
        result("misp", M, {"events_found": 4}),
        ["⚠ misp: threat detected (4 events found)", "   └─ Threat Level: malicious"],
    ),
    "misp_no_events": (result("misp", S, {"events_found": 0}), ["✓ misp: safe"]),
    "other_provider_threat": (
        result("urlscan", SUS),
        ["⚠ urlscan: threat detected", "   └─ Threat Level: suspicious"],
    ),
    "error": (
        result("yara", ERR, {"status": "error"}, "download failed"),
        ["x yara: error"],
    ),
    "unavailable": (
        result("google_sb", ERR, {"status": "unavailable"}, "not available"),
        ["x google_sb: unavailable"],
    ),
}


@pytest.mark.parametrize("case", VERBOSE_CASES)
def test_robot_verbose_summary_line(case, capsys):
    provider_result, expected = VERBOSE_CASES[case]
    OutputService(make_request(), None, None, None).robot_verbose_summary(
        [provider_result], TARGET
    )
    lines = capsys.readouterr().out.splitlines()
    assert lines[:4] == HEADER
    assert lines[4:] == expected
