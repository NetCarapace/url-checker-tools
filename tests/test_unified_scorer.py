"""Tests for the unified threat scorer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer
from url_checker_tools.core.results import ProviderResult, ThreatLevel


def make_result(provider, threat_level, error=None):
    return ProviderResult(
        provider=provider,
        target="https://example.test",
        is_threat=threat_level in (ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL),
        threat_level=threat_level,
        confidence=0.9,
        details={"status": "unavailable"} if error else {},
        error_message=error,
    )


def test_verdict_unknown_when_no_provider_ran():
    scorer = UnifiedThreatScorer()
    unavailable = [make_result("virustotal", ThreatLevel.ERROR, "not available")]
    for results in ([], unavailable):
        score = scorer.calculate_threat_score(results)
        assert score["verdict"] == "UNKNOWN"
        assert score["provider_count"] == 0


def test_providers_that_did_not_run_do_not_change_the_score():
    scorer = UnifiedThreatScorer()
    ran = [
        make_result("virustotal", ThreatLevel.MALICIOUS),
        make_result("link_analyzer", ThreatLevel.SAFE),
    ]
    not_run = [make_result("google_sb", ThreatLevel.ERROR, "not available")]
    assert scorer.calculate_threat_score(
        ran + not_run
    ) == scorer.calculate_threat_score(ran)
    assert (
        scorer.calculate_threat_score([make_result("whois", ThreatLevel.SAFE)])[
            "verdict"
        ]
        == "SAFE"
    )
