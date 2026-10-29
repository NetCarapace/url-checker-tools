"""Characterization tests: pin the current CLI output (stdout, logs) before refactoring.

Snapshots live in tests/snapshots/. They record behavior as it is, bugs included.
Regenerate after an intended change with: UPDATE_SNAPSHOTS=1 pytest tests/test_cli_characterization.py
"""

import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.cli.app import URLCheckerCLI
from url_checker_tools.config import logging_config
from url_checker_tools.core.results import ProviderResult, ThreatLevel

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
TARGET = "http://example.test/login"
FIXED_TS = datetime(2026, 1, 1, tzinfo=timezone.utc)

SAFE = {"is_threat": False, "threat_level": ThreatLevel.SAFE, "confidence": 0.9}
RESULTS = {
    "whois": {
        **SAFE,
        "details": {
            "domain_name": "example.test",
            "registrar": "Example Registrar",
            "domain_age_days": 9000,
        },
    },
    "link_analyzer": {
        **SAFE,
        "details": {
            "redirect_count": 1,
            "final_url": "https://example.test/login",
            "domain_changed": False,
            "resolved_ips": ["192.0.2.10", "2001:db8::10"],
        },
    },
    "misp": {**SAFE, "details": {"events_found": 0}},
    "whalebone": {
        **SAFE,
        "details": {"threat_types": [], "categories": ["news"], "max_accuracy": 0},
    },
    "virustotal": {
        "is_threat": True,
        "threat_level": ThreatLevel.MALICIOUS,
        "confidence": 0.8,
        "details": {
            "malicious_count": 5,
            "total_engines": 90,
            "categories": ["phishing", "Phishing"],
        },
    },
    "yara": {
        **SAFE,
        "details": {"scan_summary": "No pattern matches", "matches": []},
    },
}


def fake_provider(name, available=True, error=None):
    """Duck-typed stand-in for a provider class (constructed with no args)."""

    class FakeProvider:
        def __init__(self):
            self.config = SimpleNamespace(verbose=False)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def is_available(self):
            return available

        def scan_with_timing(self, target):
            if error:
                raise RuntimeError(error)
            return ProviderResult(
                provider=name,
                target=target,
                timestamp=FIXED_TS,
                execution_time=0.5,
                **RESULTS[name],
            )

    return FakeProvider


FAKE_PROVIDERS = {
    **{name: fake_provider(name) for name in RESULTS},
    "google_sb": fake_provider("google_sb", available=False),
    "abuseipdb": fake_provider("abuseipdb", error="connection refused"),
}


class FakeMISPReporter:
    def __init__(self, verbose=False):
        pass

    def is_available(self):
        return True

    def create_event(self, target, results, session_id):
        return {"event_id": "42", "uuid": "00000000-0000-0000-0000-000000000042"}


EXTRA = ["--providers", "virustotal,google_sb,yara,abuseipdb"]
CASES = {
    "human": EXTRA,
    "human_score_verbose": EXTRA + ["--score", "--verbose"],
    "json_score": EXTRA + ["--format", "json", "--score"],
    "synthesis": EXTRA + ["--format", "synthesis"],
    "synthesis_score": EXTRA + ["--format", "synthesis", "--score"],
    "log": EXTRA + ["--log"],
    "robot": ["--robot"],
    "robot_verbose": ["--robot", "--verbose"],
    "robot_misp_report": ["--robot", "--misp-report"],
}


def mask(text):
    """Replace values that change on every run."""
    text = re.sub(r"datetime\.datetime\([^)]*\)", "<datetime>", text)
    text = re.sub(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?", "<ts>", text
    )
    return re.sub(r"\d{4}-\d{2}-\d{2}", "<date>", text)


def run_cli(argv):
    """Run the CLI like the shell does and return (exit code, stdout, stderr)."""
    cli = URLCheckerCLI()
    cli.available_providers = FAKE_PROVIDERS
    with patch.object(sys, "argv", ["url-checker", *argv]):
        try:
            cli.main()
            return 0
        except SystemExit as e:
            return e.code


@pytest.mark.parametrize("case", CASES)
def test_cli_output_matches_snapshot(case, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)  # WorkflowLogger writes to the relative data/logs
    monkeypatch.setattr(logging_config, "_global_logger", None)

    with patch(
        "url_checker_tools.integrations.misp_reporter.MISPReporter", FakeMISPReporter
    ):
        code = run_cli([TARGET, "--sid", "snap", *CASES[case]])
    out, err = capsys.readouterr()

    parts = [f"exit: {code}", "--- stdout ---", out, "--- stderr ---", err]
    for log in sorted((tmp_path / "data" / "logs" / "sessions").rglob("*")):
        if log.is_file():
            parts += [f"--- {log.name} ---", log.read_text(encoding="utf-8")]
    actual = mask("\n".join(parts))

    snapshot = SNAPSHOT_DIR / f"{case}.txt"
    if os.environ.get("UPDATE_SNAPSHOTS") or not snapshot.exists():
        snapshot.parent.mkdir(exist_ok=True)
        snapshot.write_text(actual, encoding="utf-8")
    assert actual == snapshot.read_text(encoding="utf-8")
