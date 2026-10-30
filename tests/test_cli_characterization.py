"""Characterization tests: pin the current CLI output (stdout, logs) before refactoring.

Snapshots live in tests/snapshots/. They record behavior as it is, bugs included.
Regenerate after an intended change with: UPDATE_SNAPSHOTS=1 pytest tests/test_cli_characterization.py
"""

import os
import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from test_helpers.fake_providers import FAKE_PROVIDERS, FakeMISPReporter, fake_provider

from url_checker_tools.cli.app import URLCheckerCLI
from url_checker_tools.config import logging_config
from url_checker_tools.services.provider_registry import ProviderRegistry

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
TARGET = "http://example.test/login"
TARGETS = {"download_links": "https://example.test/setup.exe"}
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
    "list_providers": ["--list-providers"],
    "providers_status": ["--providers-status"],
    "auto_scan_files": EXTRA + ["--auto-scan-files", "--verbose"],
    "download_links": EXTRA + ["--download", "--auto-scan-files", "--verbose"],
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
    cli.registry = ProviderRegistry(FAKE_PROVIDERS)
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
        code = run_cli([TARGETS.get(case, TARGET), "--sid", "snap", *CASES[case]])
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


def test_robot_result_unknown_when_no_provider_ran(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(logging_config, "_global_logger", None)
    cli = URLCheckerCLI()
    cli.registry = ProviderRegistry(
        {name: fake_provider(name, available=False) for name in FAKE_PROVIDERS}
    )
    with patch.object(sys, "argv", ["url-checker", TARGET, "--robot", "--sid", "snap"]):
        cli.main()
    assert "RESULT: UNKNOWN (0/100)" in capsys.readouterr().out
