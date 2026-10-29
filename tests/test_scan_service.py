"""Tests for the scan loop and the events it reports."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_helpers.fake_providers import FAKE_PROVIDERS

from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer
from url_checker_tools.services.file_scan_service import FileScanService
from url_checker_tools.services.provider_registry import ProviderRegistry
from url_checker_tools.services.scan_request import ScanRequest
from url_checker_tools.services.scan_service import ScanService

TARGET = "http://example.test/login"
# whois runs, google_sb is not configured, abuseipdb raises, "nope" is not registered
PROVIDERS = ("whois", "google_sb", "abuseipdb", "nope")


class RecordingEvents:
    """Records every event call as (event name, positional args)."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, event):
        return lambda *args: self.calls.append((event, args))


def make_request(robot=False):
    return ScanRequest(
        target=TARGET,
        providers=PROVIDERS,
        session_id="test",
        format="human",
        raw=False,
        robot=robot,
        verbose=False,
        log=False,
        score=False,
        score_detail=False,
        misp_report=False,
        auto_scan_files=False,
        download=False,
        workflow=None,
    )


def run_scan(robot=False):
    events = RecordingEvents()
    service = ScanService(ProviderRegistry(FAKE_PROVIDERS), None, FileScanService(None))
    results = service.run(make_request(robot), events)
    return results, events.calls


def test_events_are_reported_in_order():
    _, calls = run_scan()
    assert [
        (event, args[0] if args and isinstance(args[0], str) else None)
        for event, args in calls
    ] == [
        ("scan_started", None),
        ("provider_started", "whois"),
        ("provider_scanning", "whois"),
        ("provider_result", "whois"),
        ("provider_started", "google_sb"),
        ("provider_unavailable", "google_sb"),
        ("provider_started", "abuseipdb"),
        ("provider_scanning", "abuseipdb"),
        ("provider_failed", "abuseipdb"),
        ("provider_unknown", "nope"),
        ("scan_finished", None),
    ]


def test_scan_finished_gets_results_and_their_score():
    results, calls = run_scan()
    event, (finished_results, scoring) = calls[-1]
    assert event == "scan_finished"
    assert finished_results is results
    assert scoring == UnifiedThreatScorer().calculate_threat_score(results)


def test_robot_mode_adds_placeholder_results_for_providers_that_did_not_run():
    plain, _ = run_scan(robot=False)
    robot, _ = run_scan(robot=True)

    assert [r.provider for r in plain] == ["whois"]
    assert [(r.provider, r.details.get("status")) for r in robot] == [
        ("whois", None),
        ("google_sb", "unavailable"),
        ("abuseipdb", "error"),
    ]
    assert all(r.is_error for r in robot[1:])


def test_scan_writes_nothing_to_stdout(capsys):
    run_scan(robot=False)
    run_scan(robot=True)
    assert capsys.readouterr().out == ""
