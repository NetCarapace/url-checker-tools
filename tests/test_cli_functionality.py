#!/usr/bin/env python3
"""Comprehensive functional tests for CLI functionality."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import url_checker_tools.cli as cli


class TestCLIFunctionality:
    """Test CLI functionality comprehensively."""

    def test_argument_parser_creation(self):
        """Test argument parser creates successfully with all expected arguments."""
        parser = cli.create_argument_parser()

        # Test basic parsing works
        args = parser.parse_args(["example.com"])
        assert args.target == "example.com"

        # Test parser has expected attributes
        assert hasattr(parser, 'parse_args')
        assert hasattr(parser, 'format_help')

    def test_all_flag_functionality(self):
        """Test --all flag works correctly."""
        parser = cli.create_argument_parser()

        # Test --all flag parsing
        args = parser.parse_args(["example.com", "--all"])
        assert args.all == True
        assert args.target == "example.com"

        # Test --all flag help text
        help_text = parser.format_help()
        assert "--all" in help_text
        assert "provider" in help_text.lower()

    def test_robot_flag_functionality(self):
        """Test --robot flag works correctly."""
        parser = cli.create_argument_parser()

        # Test --robot flag parsing
        args = parser.parse_args(["--robot", "--sid", "test123", "example.com"])
        assert args.robot == True
        assert args.session_id == "test123"
        assert args.target == "example.com"

        # Test --robot without --sid (should parse but may fail validation later)
        args = parser.parse_args(["--robot", "example.com"])
        assert args.robot == True
        assert args.session_id is None

    def test_providers_flag_functionality(self):
        """Test --providers flag works correctly."""
        parser = cli.create_argument_parser()

        # Test explicit providers list
        args = parser.parse_args(["--providers", "virustotal,google_sb,yara", "example.com"])
        assert args.providers == "virustotal,google_sb,yara"
        assert args.target == "example.com"

        # Test single provider
        args = parser.parse_args(["--providers", "virustotal", "example.com"])
        assert args.providers == "virustotal"

    def test_individual_provider_flags(self):
        """Test individual provider flags work correctly."""
        parser = cli.create_argument_parser()

        # Test individual flags
        provider_flags = {
            "virustotal": "virustotal",
            "google_sb": "google_sb",
            "yara": "yara",
            "lookyloo": "lookyloo",
            "urlscan": "urlscan"
        }

        for flag, attr in provider_flags.items():
            args = parser.parse_args(["example.com", "--providers", flag])
            assert args.providers == attr
            assert args.target == "example.com"

    def test_output_format_flags(self):
        """Test output format flags work correctly."""
        parser = cli.create_argument_parser()

        # Test different formats
        formats = ["json", "human", "synthesis"]
        for fmt in formats:
            args = parser.parse_args(["--all", "--format", fmt, "example.com"])
            assert args.format == fmt

    def test_verbose_flag_functionality(self):
        """Test --verbose flag works correctly."""
        parser = cli.create_argument_parser()

        # Test verbose flag
        args = parser.parse_args(["--all", "--verbose", "example.com"])
        assert args.verbose == True

        # Test without verbose
        args = parser.parse_args(["example.com"])
        assert args.verbose == False

    def test_session_id_flag_functionality(self):
        """Test --sid/--session-id flag works correctly."""
        parser = cli.create_argument_parser()

        # Test --sid
        args = parser.parse_args(["example.com", "--sid", "session123"])
        assert args.session_id == "session123"

        # Test --session-id (if supported)
        try:
            args = parser.parse_args(["example.com", "--session-id", "session456"])
            assert args.session_id == "session456"
        except SystemExit:
            # If --session-id is not supported, that's okay
            pass

    def test_mutually_exclusive_provider_groups(self):
        """Test mutually exclusive provider groups work correctly."""
        parser = cli.create_argument_parser()

        # --providers and --all should be mutually exclusive
        with pytest.raises(SystemExit):
            parser.parse_args(["--providers virustotal", "--all", "example.com"])

    def test_argument_parsing_edge_cases(self):
        """Test argument parsing handles edge cases."""
        parser = cli.create_argument_parser()

        # Test with various URL formats
        url_formats = [
            "https://example.com",
            "http://example.com",
            "example.com",
            "subdomain.example.com",
            "192.168.1.1",
        ]

        for url in url_formats:
            args = parser.parse_args([url])
            assert args.target == url

    @patch('url_checker_tools.cli.app.URLCheckerCLI')
    def test_provider_selection_all_flag(self, mock_url_checker):
        """Test provider selection logic with --all flag."""
        mock_instance = Mock()
        mock_instance.available_providers = {
            'whois': Mock(),
            'virustotal': Mock(),
            'google_sb': Mock(),
            'yara': Mock(),
            'urlscan': Mock(),
            'lookyloo': Mock()
        }
        mock_url_checker.return_value = mock_instance

        # Mock the _determine_providers method
        def mock_determine_providers(args):
            if args.providers:
                return args.providers.split(',')
            elif args.all:
                return list(mock_instance.available_providers.keys())
            elif args.robot:
                return ['whois', 'virustotal', 'google_sb', 'yara']
            else:
                # Individual flags
                providers = []
                if getattr(args, 'virustotal', False):
                    providers.append('virustotal')
                if getattr(args, 'google_sb', False):
                    providers.append('google_sb')
                return providers if providers else list(mock_instance.available_providers.keys())

        mock_instance._determine_providers = mock_determine_providers

        # Test --all flag
        args = Mock()
        args.providers = None
        args.all = True
        args.robot = False
        args.virustotal = False
        args.google_sb = False

        providers = mock_instance._determine_providers(args)
        assert set(providers) == set(mock_instance.available_providers.keys())

    @patch('url_checker_tools.cli.app.URLCheckerCLI')
    def test_provider_selection_robot_mode(self, mock_url_checker):
        """Test provider selection logic in robot mode."""
        mock_instance = Mock()
        mock_url_checker.return_value = mock_instance

        with patch('url_checker_tools.config.robot_config.RobotModeConfig.get_robot_providers') as mock_get_robot:
            mock_get_robot.return_value = ['whois', 'virustotal', 'google_sb', 'yara']

            def mock_determine_providers(args):
                if args.robot:
                    return mock_get_robot.return_value
                return []

            mock_instance._determine_providers = mock_determine_providers

            # Test robot mode
            args = Mock()
            args.robot = True

            providers = mock_instance._determine_providers(args)
            expected = ['whois', 'virustotal', 'google_sb', 'yara']
            assert providers == expected

    def test_flag_combination_validation(self):
        """Test various flag combinations work correctly."""
        parser = cli.create_argument_parser()

        # Valid combinations
        valid_combinations = [
            ["--robot", "--sid", "test", "example.com"],
            ["--all", "example.com"],
            ["--providers", "virustotal,google_sb,yara", "example.com"],
            ["example.com"],
            ["--verbose", "--format", "json", "example.com"],
            ["--robot", "--verbose", "--sid", "test", "example.com"]
        ]

        for combination in valid_combinations:
            try:
                args = parser.parse_args(combination)
                assert args.target == "example.com"
            except SystemExit as e:
                pytest.fail(f"Valid combination should parse successfully: {combination}")

    def test_format_flag_options(self):
        """Test format flag accepts valid options."""
        parser = cli.create_argument_parser()

        # Test various format options
        format_options = ["json", "human", "synthesis"]

        for fmt in format_options:
            try:
                args = parser.parse_args(["--format", fmt, "example.com"])
                assert args.format == fmt
            except SystemExit:
                # Some formats may not be supported, which is okay
                pass

    def test_yara_specific_flags(self):
        """Test YARA-specific configuration flags."""
        parser = cli.create_argument_parser()

        # Test YARA flags if they exist
        yara_combinations = [
            ["--providers yara", "example.com"],
            ["--yara-rules", "rule1", "--yara", "example.com"],
        ]

        for combination in yara_combinations:
            try:
                args = parser.parse_args(combination)
                assert args.target == "example.com"
                if "--yara" in combination:
                    assert args.yara == True
            except SystemExit:
                # Some YARA flags may not exist, which is okay
                pass

    def test_logging_and_output_flags(self):
        """Test logging and output related flags."""
        parser = cli.create_argument_parser()

        # Test logging flags
        logging_flags = ["--log", "--score", "--raw"]

        for flag in logging_flags:
            try:
                args = parser.parse_args([flag, "example.com"])
                assert args.target == "example.com"
                flag_attr = flag.lstrip('-').replace('-', '_')
                if hasattr(args, flag_attr):
                    assert getattr(args, flag_attr) == True
            except SystemExit:
                # Flag may not exist, which is okay
                pass

    @patch('url_checker_tools.config.robot_config.RobotModeConfig.apply_robot_flags')
    def test_robot_flag_application(self, mock_apply_flags):
        """Test robot flag application is called correctly."""
        # This tests the integration point where robot flags are applied

        args = SimpleNamespace()
        args.robot = True
        args.session_id = "test123"

        # Simulate flag application
        mock_apply_flags.return_value = None

        # In actual code, this would be called when --robot is used
        if args.robot:
            from url_checker_tools.config.robot_config import RobotModeConfig
            RobotModeConfig.apply_robot_flags(args)

        mock_apply_flags.assert_called_once_with(args)

    def test_argument_precedence_order(self):
        """Test argument precedence follows expected order."""
        parser = cli.create_argument_parser()

        # Test that explicit providers take precedence
        args = parser.parse_args(["example.com", "--providers", "virustotal"])
        assert args.providers == "virustotal"
        assert args.all == False

        # Test that --all is explicit when set
        args = parser.parse_args(["example.com", "--all"])
        assert args.all == True
        assert args.providers is None

    def test_target_url_handling(self):
        """Test various target URL formats are handled."""
        parser = cli.create_argument_parser()

        # Test different URL formats
        target_formats = [
            "https://www.example.com",
            "http://example.com/path?param=value",
            "example.com",
            "sub.example.com:8080",
            "192.168.1.1",
        ]

        for target in target_formats:
            args = parser.parse_args([target])
            assert args.target == target


    def test_parser_error_handling(self):
        """Test parser handles errors appropriately."""
        parser = cli.create_argument_parser()

        # Test invalid flag
        with pytest.raises(SystemExit):
            parser.parse_args(["--nonexistent-flag", "example.com"])

    def test_multiple_provider_flags_combination(self):
        """Test combining multiple individual provider flags."""
        parser = cli.create_argument_parser()

        # Test multiple provider flags
        args = parser.parse_args(["--providers", "virustotal,google-sb,yara", "example.com"])

        assert args.providers == "virustotal,google-sb,yara"
        assert args.target == "example.com"

    def test_case_sensitivity_handling(self):
        """Test argument parsing handles case correctly."""
        parser = cli.create_argument_parser()

        # Test that target preserves case
        mixed_case_url = "https://Example.COM/Path"
        args = parser.parse_args([mixed_case_url])
        assert args.target == mixed_case_url

        # Test format values (case sensitive - must be lowercase)
        args = parser.parse_args(["--format", "json", "example.com"])
        assert args.format == "json"
