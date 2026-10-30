"""Tests for robot log writing and how the CLI reports it."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.cli.output_service import OutputService
from url_checker_tools.config.logging_config import WorkflowLogger
from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.services.robot_log_service import RobotLogBuilder
from url_checker_tools.services.scan_request import ScanRequest

TARGET = "https://example.test/login"


def make_request():
    return ScanRequest(
        target=TARGET,
        providers=("whois",),
        session_id="robot-test",
        format="synthesis",
        raw=False,
        robot=True,
        verbose=False,
        log=True,
        score=True,
        score_detail=False,
        misp_report=False,
        auto_scan_files=False,
        download=False,
        workflow=None,
    )


def test_write_returns_both_log_paths(tmp_path, capsys):
    logger = WorkflowLogger(log_dir=str(tmp_path), session_id="robot-test")
    result = ProviderResult("whois", TARGET, False, ThreatLevel.SAFE, 0.9, {})

    synthesis_path, detailed_path = RobotLogBuilder("robot-test", logger).write(
        TARGET, [result], "{}"
    )

    assert synthesis_path.suffix == ".log" and detailed_path.suffix == ".dlog"
    assert (
        json.loads(synthesis_path.read_text())["session_metadata"]["session_id"]
        == "robot-test"
    )
    assert json.loads(detailed_path.read_text())["results"]["target"] == TARGET
    assert capsys.readouterr().out == ""


def test_cli_prints_log_paths(capsys):
    output = OutputService(
        make_request(), None, lambda *args: (Path("a.log"), Path("a.dlog")), None
    )
    output._write_robot_logs(TARGET, [], "{}", None)
    assert capsys.readouterr().out == (
        "[INFO] Robot logs created:\n  Synthesis: a.log\n  Detailed: a.dlog\n"
    )


def test_cli_prints_robot_log_errors(capsys):
    def failing_write(*args):
        raise ValueError("Session ID required for dual logging")

    OutputService(make_request(), None, failing_write, None)._write_robot_logs(
        TARGET, [], "{}", None
    )
    assert capsys.readouterr().out == (
        "[ERROR] Failed to create robot logs: Session ID required for dual logging\n"
    )


def test_failed_log_write_is_reported_not_claimed_as_created(tmp_path, capsys):
    """A log file that cannot be written must not be reported as created."""
    logger = WorkflowLogger(log_dir=str(tmp_path), session_id="robot-test")
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    logger.log_dir = blocked
    (blocked / "sessions").write_text("a file where the directory should be")
    builder = RobotLogBuilder("robot-test", logger)
    result = ProviderResult("whois", TARGET, False, ThreatLevel.SAFE, 0.9, {})

    output = OutputService(make_request(), None, builder.write, None)
    output._write_robot_logs(TARGET, [result], "{}", None)

    out = capsys.readouterr().out
    assert out.startswith("[ERROR] Failed to create robot logs:")
    assert "Robot logs created" not in out


def test_failed_session_log_write_raises(tmp_path):
    logger = WorkflowLogger(log_dir=str(tmp_path), session_id="s")
    path, _ = logger._create_log_path(TARGET, "s")
    path.parent.mkdir(parents=True)
    path.mkdir()  # a directory where the log file should be
    with pytest.raises(OSError):
        logger.create_session_log(TARGET, "output", "human")
