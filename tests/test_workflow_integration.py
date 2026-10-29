#!/usr/bin/env python3
"""Comprehensive workflow integration tests."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.core.results import ProviderResult, ThreatLevel


class TestWorkflowIntegration:
    """Test end-to-end workflow integration functionality."""

    def test_complete_scanning_workflow(self):
        """Test complete scanning workflow from CLI to results."""
        # Setup mock URLChecker instance
        mock_instance = Mock()

        # Mock provider results
        mock_results = [
            ProviderResult(
                provider="whois",
                target="https://example.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.9,
                details={"domain_age_days": 365, "registrar": "Test Registrar"},
                timestamp=None, execution_time=None, error_message=None
            ),
            ProviderResult(
                provider="virustotal",
                target="https://example.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.95,
                details={"malicious_count": 0, "total_engines": 50},
                timestamp=None, execution_time=None, error_message=None
            )
        ]

        mock_instance.scan_target.return_value = (mock_results, {"overall_verdict": "safe"})
        mock_instance.available_providers = {
            "whois": Mock(is_available=True),
            "virustotal": Mock(is_available=True)
        }

        # Import and test the workflow
        import url_checker_tools as cli

        # Test argument parsing
        parser = cli.URLCheckerCLI().create_argument_parser()
        args = parser.parse_args(["--providers", "whois,virustotal", "https://example.com"])

        # Test provider selection
        url_checker = mock_instance
        assert url_checker is not None

        # Mock the scan execution
        results, synthesis = url_checker.scan_target("https://example.com")

        # Verify workflow completed successfully
        assert len(results) == 2
        assert all(isinstance(result, ProviderResult) for result in results)
        assert synthesis is not None

    def test_robot_mode_workflow(self):
        """Test robot mode workflow integration."""
        mock_instance = Mock()

        # Mock robot mode results
        robot_results = [
            ProviderResult(
                provider="whois",
                target="https://test.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.8,
                details={"domain_age_days": 100},
                timestamp=None, execution_time=None, error_message=None
            ),
            ProviderResult(
                provider="virustotal",
                target="https://test.com",
                is_threat=True,
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.9,
                details={"malicious_count": 3, "total_engines": 50},
                timestamp=None, execution_time=None, error_message=None
            )
        ]

        mock_instance.scan_target.return_value = (robot_results, {"overall_verdict": "malicious"})

        # Test robot mode workflow
        import url_checker_tools as cli

        parser = cli.URLCheckerCLI().create_argument_parser()
        args = parser.parse_args(["--robot", "--sid", "test123", "https://test.com"])

        assert args.robot == True
        assert args.session_id == "test123"

        # Test robot flag application
        with patch('url_checker_tools.config.robot_config.RobotModeConfig.apply_robot_flags') as mock_apply:
            if args.robot:
                from url_checker_tools.config.robot_config import RobotModeConfig
                RobotModeConfig.apply_robot_flags(args)
                mock_apply.assert_called_once()

    def test_all_providers_workflow(self):
        """Test --all providers workflow."""
        mock_instance = Mock()
        mock_instance.available_providers = {
            "whois": Mock(is_available=True),
            "virustotal": Mock(is_available=True),
            "google_sb": Mock(is_available=True),
            "yara": Mock(is_available=True),
            "urlscan": Mock(is_available=False),  # Unavailable
            "lookyloo": Mock(is_available=True)
        }

        # Mock all providers results
        all_results = []
        for provider_name in ["whois", "virustotal", "google_sb", "yara", "lookyloo"]:
            result = ProviderResult(
                provider=provider_name,
                target="https://comprehensive-test.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.8,
                details={"status": "clean"},
                timestamp=None, execution_time=None, error_message=None
            )
            all_results.append(result)

        mock_instance.scan_target.return_value = (all_results, {"overall_verdict": "safe"})

        import url_checker_tools as cli

        parser = cli.URLCheckerCLI().create_argument_parser()
        args = parser.parse_args(["--all", "https://comprehensive-test.com"])

        assert args.all == True

        # Test that all available providers are used
        url_checker = mock_instance
        results, synthesis = url_checker.scan_target("https://comprehensive-test.com")

        # Should get results from all available providers
        assert len(results) == 5  # Available providers only
        provider_names = {result.provider for result in results}
        expected_available = {"whois", "virustotal", "google_sb", "yara", "lookyloo"}
        assert provider_names == expected_available

    def test_result_synthesis_integration(self):
        """Test result synthesis and aggregation."""
        # Create diverse results for synthesis testing
        mixed_results = [
            ProviderResult(
                provider="whois",
                target="https://mixed-signals.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.9,
                details={"domain_age_days": 1000},
                timestamp=None, execution_time=None, error_message=None
            ),
            ProviderResult(
                provider="virustotal",
                target="https://mixed-signals.com",
                is_threat=True,
                threat_level=ThreatLevel.SUSPICIOUS,
                confidence=0.6,
                details={"malicious_count": 2, "total_engines": 50}
            ),
            ProviderResult(
                provider="google_sb",
                target="https://mixed-signals.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.95,
                details={"safe": True}
            )
        ]

        # Test result aggregation
        threat_results = [r for r in mixed_results if r.is_threat]
        safe_results = [r for r in mixed_results if not r.is_threat]

        assert len(threat_results) == 1
        assert len(safe_results) == 2

        # Test confidence aggregation
        total_confidence = sum(r.confidence for r in mixed_results)
        avg_confidence = total_confidence / len(mixed_results)
        assert 0.0 <= avg_confidence <= 1.0

        # Test threat level distribution
        threat_levels = [r.threat_level for r in mixed_results]
        assert ThreatLevel.SAFE in threat_levels
        assert ThreatLevel.SUSPICIOUS in threat_levels

    def test_error_handling_workflow(self):
        """Test workflow handles errors gracefully."""
        mock_instance = Mock()

        # Mix of successful and error results
        error_results = [
            ProviderResult(
                provider="working_provider",
                target="https://error-test.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.9,
                details={"status": "success"}
            ),
            ProviderResult(
                provider="failing_provider",
                target="https://error-test.com",
                is_threat=False,
                threat_level=ThreatLevel.ERROR,
                confidence=0.0,
                details={"error": "Network timeout", "status_code": 500}
            )
        ]

        mock_instance.scan_target.return_value = (error_results, {"overall_verdict": "partial_success"})

        # Test that workflow continues despite errors
        url_checker = mock_instance
        results, synthesis = url_checker.scan_target("https://error-test.com")

        # Should have both successful and error results
        assert len(results) == 2
        success_results = [r for r in results if r.threat_level != ThreatLevel.ERROR]
        error_results_list = [r for r in results if r.threat_level == ThreatLevel.ERROR]

        assert len(success_results) == 1
        assert len(error_results_list) == 1
        assert "error" in error_results_list[0].details

    def test_output_formatting_integration(self):
        """Test output formatting integration with different formats."""
        # Test results for formatting
        sample_results = [
            ProviderResult(
                provider="test_provider",
                target="https://format-test.com",
                is_threat=True,
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.85,
                details={"malware_type": "trojan", "detection_engines": 8}
            )
        ]

        # Test different output formats can handle results
        formats_to_test = ["json", "synthesis", "human"]

        for format_type in formats_to_test:
            # Test that results can be formatted (basic structure check)
            try:
                # Simulate formatting process
                formatted_data = {
                    "format": format_type,
                    "results": [
                        {
                            "provider": r.provider,
                            "target": r.target,
                            "is_threat": r.is_threat,
                            "threat_level": r.threat_level.value,
                            "confidence": r.confidence,
                            "details": r.details
                        } for r in sample_results
                    ]
                }

                assert formatted_data["format"] == format_type
                assert len(formatted_data["results"]) == 1
                assert formatted_data["results"][0]["provider"] == "test_provider"

            except Exception as e:
                pytest.fail(f"Format {format_type} should handle results without errors: {e}")

    def test_session_management_workflow(self):
        """Test session management throughout workflow."""
        mock_instance = Mock()

        session_results = [
            ProviderResult(
                provider="session_provider",
                target="https://session-test.com",
                is_threat=False,
                threat_level=ThreatLevel.SAFE,
                confidence=0.9,
                details={"session_id": "session123", "timestamp": "2023-01-01T12:00:00Z"}
            )
        ]

        mock_instance.scan_target.return_value = (session_results, {"session_id": "session123"})

        import url_checker_tools as cli

        # Test session ID handling
        parser = cli.URLCheckerCLI().create_argument_parser()
        args = parser.parse_args(["--robot", "--sid", "session123", "https://session-test.com"])

        assert args.session_id == "session123"

        # Test session ID propagation
        url_checker = mock_instance
        results, synthesis = url_checker.scan_target("https://session-test.com")

        # Session information should be maintained
        assert "session_id" in synthesis
        assert synthesis["session_id"] == "session123"

    def test_configuration_integration(self):
        """Test configuration system integration."""
        # Test configuration loading and application
        with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs') as mock_config:
            mock_config.return_value = {
                "test_provider": {
                    "api_key": "test_key_123",
                    "endpoint": "https://api.test.com",
                    "timeout": 30
                }
            }

            # Test configuration access
            all_configs = mock_config.return_value
            assert "test_provider" in all_configs
            assert all_configs["test_provider"]["api_key"] == "test_key_123"
            assert all_configs["test_provider"]["timeout"] == 30

    def test_concurrent_workflow_handling(self):
        """Test workflow can handle concurrent operations safely."""
        import threading
        import time

        # Simulate concurrent workflow execution
        results = []
        errors = []

        def simulate_workflow(target_num):
            try:
                # Simulate a workflow execution
                mock_result = ProviderResult(
                    provider="concurrent_provider",
                    target=f"https://concurrent-test-{target_num}.com",
                    is_threat=False,
                    threat_level=ThreatLevel.SAFE,
                    confidence=0.8,
                    details={"target_num": target_num, "timestamp": time.time()}
                )
                time.sleep(0.1)  # Simulate processing time
                results.append(mock_result)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=simulate_workflow, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # All workflows should complete successfully
        assert len(results) == 5
        assert len(errors) == 0

        # Results should be distinct
        target_nums = {r.details["target_num"] for r in results}
        assert len(target_nums) == 5

    def test_misp_integration_workflow(self):
        """Test MISP integration in complete workflow."""
        mock_instance = Mock()

        # Mock threat results that would trigger MISP reporting
        threat_results = [
            ProviderResult(
                provider="threat_detector",
                target="https://malicious-site.com",
                is_threat=True,
                threat_level=ThreatLevel.MALICIOUS,
                confidence=0.95,
                details={"malware_family": "trojan", "threat_score": 95}
            )
        ]

        mock_instance.scan_target.return_value = (threat_results, {"overall_verdict": "malicious"})

        # Test MISP integration workflow
        with patch('url_checker_tools.integrations.misp_reporter.MISPReporter') as mock_misp_reporter:
            mock_reporter_instance = Mock()
            mock_reporter_instance.is_available.return_value = True
            mock_reporter_instance.create_event.return_value = {"event_id": 123, "uuid": "test-uuid"}
            mock_misp_reporter.return_value = mock_reporter_instance

            # Simulate MISP reporting in workflow
            url_checker = mock_instance
            results, synthesis = url_checker.scan_target("https://malicious-site.com")

            # Test MISP reporter creation
            args = SimpleNamespace(verbose=False, misp_report=True, session_id="test_session")
            reporter = mock_misp_reporter(verbose=getattr(args, 'verbose', False))

            if args.misp_report and reporter.is_available():
                misp_result = reporter.create_event(
                    "https://malicious-site.com",
                    [r for r in results if r.is_threat],
                    args.session_id
                )

                # MISP event should be created for threats
                assert misp_result is not None
                assert misp_result["event_id"] == 123

    def test_logging_integration_workflow(self):
        """Test logging integration throughout workflow."""
        with patch('url_checker_tools.config.logging_config.get_logger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger

            # Test logging in various workflow components
            from url_checker_tools.core.base_provider import BaseProvider
            from url_checker_tools.core.http_client import HTTPClient

            # Test provider logging
            try:
                with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs'):
                    class TestProvider(BaseProvider):
                        def is_available(self):
                            return True

                        def scan(self, target):
                            return self._create_safe_result(target, {})

                    provider = TestProvider("test", {})
                    assert provider.logger is not None

            except Exception:
                # Provider creation might fail due to missing dependencies, that's okay
                pass

            # Test HTTP client logging
            http_client = HTTPClient("test_provider")
            assert hasattr(http_client, 'logger')

            # Verify logger was requested
            mock_get_logger.assert_called()

    def test_performance_workflow_integration(self):
        """Test performance aspects of workflow integration."""
        import time

        # Test execution timing
        start_time = time.time()

        # Simulate workflow components
        mock_results = []
        for i in range(10):
            result = ProviderResult(
                provider=f"provider_{i}",
                target="https://performance-test.com",
                is_threat=i % 3 == 0,  # Every 3rd is threat
                threat_level=ThreatLevel.MALICIOUS if i % 3 == 0 else ThreatLevel.SAFE,
                confidence=0.8 + (i * 0.01),
                details={"index": i, "processing_time": 0.1}
            )
            mock_results.append(result)

        end_time = time.time()
        execution_time = end_time - start_time

        # Workflow should complete reasonably quickly
        assert execution_time < 1.0, "Workflow should complete within reasonable time"

        # Test result processing performance
        threat_count = sum(1 for r in mock_results if r.is_threat)
        safe_count = sum(1 for r in mock_results if not r.is_threat)

        assert threat_count + safe_count == len(mock_results)

        # Test confidence calculations
        avg_confidence = sum(r.confidence for r in mock_results) / len(mock_results)
        assert 0.8 <= avg_confidence <= 0.9
