"""Tests for the immutable scan request."""

import dataclasses
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.cli.app import create_argument_parser
from url_checker_tools.config.robot_config import RobotModeConfig
from url_checker_tools.services.scan_request import ScanRequest


def parse(argv):
    """Parse like the CLI does, including robot mode defaults (which read sys.argv)."""
    with patch.object(sys, "argv", ["url-checker", *argv]):
        args = create_argument_parser().parse_args(argv)
        if args.robot:
            RobotModeConfig.apply_robot_flags(args)
    return args


def test_from_args_plain_scan():
    args = parse(["example.com", "--format", "json", "--verbose"])
    request = ScanRequest.from_args(args, ["whois", "link_analyzer"], "sid1")

    assert request.target == "example.com"
    assert request.providers == ("whois", "link_analyzer")
    assert request.session_id == "sid1"
    assert request.format == "json"
    assert request.verbose is True
    assert request.robot is False
    assert request.score is False


def test_from_args_robot_mode_defaults():
    args = parse(["example.com", "--robot", "--sid", "s2"])
    request = ScanRequest.from_args(args, ["whois"], "s2")

    assert request.robot is True
    assert request.format == "synthesis"
    assert request.log is True
    assert request.score is True


def test_request_is_immutable():
    request = ScanRequest.from_args(parse(["example.com"]), ["whois"], "s3")
    with pytest.raises(dataclasses.FrozenInstanceError):
        request.target = "other.com"


def test_yara_options_become_yara_config_overrides():
    args = parse(
        [
            "example.com",
            "--yara-rules",
            "a.yar",
            "rules/",
            "--yara-timeout",
            "5",
            "--yara-max-bytes",
            "100",
        ]
    )
    request = ScanRequest.from_args(args, ["yara"], "s4")
    assert request.config_overrides("yara") == {
        "rule_paths": ["a.yar", "rules/"],
        "timeout": 5,
        "max_file_size": 100,
    }
    assert request.config_overrides("virustotal") == {}


def test_yara_option_defaults_match_the_yara_provider_defaults():
    from url_checker_tools.config.provider_config import ProviderConfigTemplate

    defaults = ScanRequest.from_args(parse(["example.com"]), ["yara"], "s5")
    config = ProviderConfigTemplate.get_yara_config()
    overrides = defaults.config_overrides("yara")
    assert overrides["timeout"] == config["timeout"]
    assert overrides["max_file_size"] == config["max_file_size"]
    assert overrides["rule_paths"] == []  # empty: the provider falls back to rules_dir
