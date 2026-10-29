"""Characterization tests for MISP reporting outcomes: returned data and printed lines."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.cli.app import URLCheckerCLI
from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.services.scan_request import ScanRequest

TARGET = "http://example.test/login"
REPORTER = "url_checker_tools.integrations.misp_reporter.MISPReporter"


def result(is_threat):
    return ProviderResult(
        provider="virustotal",
        target=TARGET,
        is_threat=is_threat,
        threat_level=ThreatLevel.MALICIOUS if is_threat else ThreatLevel.SAFE,
        confidence=0.9,
        details={},
    )


THREAT = [result(True)]
SAFE = [result(False)]


def fake_reporter(available=True, event=None, error=None):
    class FakeReporter:
        def __init__(self, verbose=False):
            pass

        def is_available(self):
            return available

        def create_event(self, target, results, session_id):
            if error:
                raise RuntimeError(error)
            return event

    return FakeReporter


def make_request(verbose):
    return ScanRequest(
        target=TARGET,
        providers=("virustotal",),
        session_id="sid",
        format="human",
        raw=False,
        robot=True,
        verbose=verbose,
        log=False,
        score=False,
        score_detail=False,
        misp_report=True,
        auto_scan_files=False,
        download=False,
        workflow=None,
    )


def run_misp(request, results, capsys):
    """Run MISP reporting the way the CLI does; return (misp_data, stdout)."""
    cli = URLCheckerCLI()
    cli.session_id = request.session_id
    misp_data = cli.handle_misp_reporting(request, results)
    return misp_data, capsys.readouterr().out


SUCCESS = fake_reporter(event={"event_id": 42, "uuid": "u-42"})
CASES = {
    "unavailable": (
        fake_reporter(available=False),
        THREAT,
        {
            "event_id": None,
            "status": "unavailable",
            "error": "MISP reporter not available - check configuration",
        },
        "[WARNING] MISP reporter not available - check configuration\n",
        "",
    ),
    "skipped_no_threats": (
        SUCCESS,
        SAFE,
        {"event_id": None, "status": "skipped_no_threats", "error": None},
        "[INFO] No threats detected - skipping MISP report\n",
        "",
    ),
    "success": (
        SUCCESS,
        THREAT,
        {"event_id": 42, "status": "success", "error": None, "uuid": "u-42"},
        "[INFO] MISP event created: Event ID 42 (UUID: u-42)\n",
        "MISP event created: 42\n",
    ),
    "failed": (
        fake_reporter(event=None),
        THREAT,
        {
            "event_id": None,
            "status": "failed",
            "error": "Failed to create MISP event",
        },
        "[ERROR] Failed to create MISP event\n",
        "",
    ),
    "error": (
        fake_reporter(error="connection refused"),
        THREAT,
        {"event_id": None, "status": "error", "error": "connection refused"},
        "[ERROR] MISP reporting failed: connection refused\n",
        "MISP reporting error: connection refused\n",
    ),
}


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("case", CASES)
def test_misp_reporting_outcome(case, verbose, capsys):
    reporter, results, expected_data, verbose_out, quiet_out = CASES[case]
    with patch(REPORTER, reporter):
        misp_data, out = run_misp(make_request(verbose), results, capsys)
    assert misp_data == expected_data
    assert out == (verbose_out if verbose else quiet_out)


@pytest.mark.parametrize("verbose", [True, False])
def test_misp_reporting_module_unavailable(verbose, capsys):
    with patch.dict(
        sys.modules, {"url_checker_tools.integrations.misp_reporter": None}
    ):
        misp_data, out = run_misp(make_request(verbose), THREAT, capsys)
    assert misp_data == {
        "event_id": None,
        "status": "module_unavailable",
        "error": "MISP integration module not available",
    }
    assert out == (
        "[WARNING] MISP integration module not available\n" if verbose else ""
    )
