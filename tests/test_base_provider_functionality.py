#!/usr/bin/env python3
"""Comprehensive functional tests for the BaseProvider system."""

import sys
import time
from pathlib import Path
from unittest.mock import Mock, patch
from typing import Dict, Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.core.exceptions import URLCheckerError


class TestProvider(BaseProvider):
    """Test provider implementation for testing BaseProvider functionality."""

    def __init__(self, provider_name: str = "test_provider", config: Dict[str, Any] = None):
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        val = getattr(self.config, 'available', None)
        return True if val is None else bool(val)

    def scan(self, target: str) -> ProviderResult:
        if target == "error.com":
            raise URLCheckerError("Test error")
        elif target == "malicious.com":
            return self._create_threat_result(target, ThreatLevel.MALICIOUS, {"malware": True})
        elif target == "suspicious.com":
            return self._create_threat_result(target, ThreatLevel.SUSPICIOUS, {"suspicious": True})
        else:
            return self._create_safe_result(target, {"clean": True})


class TestBaseProviderFunctionality:
    """Test BaseProvider functionality comprehensively."""

    def test_provider_initialization_default_config(self):
        """Test provider initialization with default configuration."""
        with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs') as mock_configs:
            mock_configs.return_value = {
                'test_provider': {
                    'api_key': 'default_key',
                    'endpoint': 'https://api.test.com'
                }
            }

            provider = TestProvider()

            assert provider.provider_name == "test_provider"
            assert hasattr(provider, 'config')
            assert hasattr(provider, 'http')
            assert hasattr(provider, 'logger')
            assert provider.config.api_key == 'default_key'
            assert provider.config.endpoint == 'https://api.test.com'

    def test_provider_initialization_custom_config(self):
        """Test provider initialization with custom configuration."""
        custom_config = {
            "api_key": "custom_key",
            "endpoint": "https://custom.api.com",
            "timeout": 60,
            "rate_limit": 2.0
        }

        provider = TestProvider("custom_provider", custom_config)

        assert provider.provider_name == "custom_provider"
        assert provider.config.api_key == "custom_key"
        assert provider.config.endpoint == "https://custom.api.com"
        assert provider.config.timeout == 60
        assert provider.config.rate_limit == 2.0

    def test_http_client_integration(self):
        """Test HTTP client is properly integrated and functional."""
        provider = TestProvider()

        # HTTP client should be available
        assert hasattr(provider, 'http')
        assert hasattr(provider.http, 'get')
        assert hasattr(provider.http, 'post')
        assert provider.http.provider_name == "test_provider"

    def test_logger_integration(self):
        """Test logger is properly integrated and functional."""
        provider = TestProvider()

        # Logger should be available
        assert hasattr(provider, 'logger')
        assert hasattr(provider.logger, 'info')
        assert hasattr(provider.logger, 'error')
        assert hasattr(provider.logger, 'debug')
        assert hasattr(provider.logger, 'warning')

    def test_create_safe_result(self):
        """Test _create_safe_result helper method."""
        provider = TestProvider()
        target = "https://safe.example.com"
        details = {"status": "clean", "scanned": True}

        result = provider._create_safe_result(target, details)

        assert isinstance(result, ProviderResult)
        assert result.provider == "test_provider"
        assert result.target == target
        assert result.is_threat == False
        assert result.threat_level == ThreatLevel.SAFE
        assert result.confidence >= 0.0
        assert result.details == details
        assert hasattr(result, 'execution_time')

    def test_create_threat_result(self):
        """Test _create_threat_result helper method."""
        provider = TestProvider()
        target = "https://malicious.example.com"
        details = {"malware_type": "trojan", "detection_count": 5}

        result = provider._create_threat_result(target, ThreatLevel.MALICIOUS, details)

        assert isinstance(result, ProviderResult)
        assert result.provider == "test_provider"
        assert result.target == target
        assert result.is_threat == True
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.confidence >= 0.0
        assert result.details == details
        assert hasattr(result, 'execution_time')

    def test_create_error_result(self):
        """Test _create_error_result helper method."""
        provider = TestProvider()
        target = "https://example.com"
        error_msg = "API request failed with status 500"

        result = provider._create_error_result(target, error_msg)

        assert isinstance(result, ProviderResult)
        assert result.provider == "test_provider"
        assert result.target == target
        assert result.is_threat == False
        assert result.threat_level == ThreatLevel.ERROR
        assert result.confidence == 0.0
        assert "error" in result.details
        assert result.details["error"] == error_msg

    def test_scan_method_safe_result(self):
        """Test scan method returns safe result correctly."""
        provider = TestProvider()
        target = "https://safe.example.com"

        result = provider.scan(target)

        assert isinstance(result, ProviderResult)
        assert result.target == target
        assert result.is_threat == False
        assert result.threat_level == ThreatLevel.SAFE
        assert result.details["clean"] == True

    def test_scan_method_threat_result(self):
        """Test scan method returns threat result correctly."""
        provider = TestProvider()
        target = "malicious.com"

        result = provider.scan(target)

        assert isinstance(result, ProviderResult)
        assert result.target == target
        assert result.is_threat == True
        assert result.threat_level == ThreatLevel.MALICIOUS
        assert result.details["malware"] == True

    def test_scan_method_suspicious_result(self):
        """Test scan method returns suspicious result correctly."""
        provider = TestProvider()
        target = "suspicious.com"

        result = provider.scan(target)

        assert isinstance(result, ProviderResult)
        assert result.target == target
        assert result.is_threat == True
        assert result.threat_level == ThreatLevel.SUSPICIOUS
        assert result.details["suspicious"] == True

    def test_scan_method_error_handling(self):
        """Test scan method error handling."""
        provider = TestProvider()
        target = "error.com"

        with pytest.raises(URLCheckerError):
            provider.scan(target)

    def test_is_available_method(self):
        """Test is_available method functionality."""
        # Provider available by default
        provider = TestProvider()
        assert provider.is_available() == True

        # Provider unavailable with config
        config = {"available": False}
        provider_unavailable = TestProvider(config=config)
        assert provider_unavailable.is_available() == False

    def test_context_manager_functionality(self):
        """Test provider works as context manager."""
        provider = TestProvider()

        with provider as p:
            assert p is provider
            result = p.scan("https://example.com")
            assert isinstance(result, ProviderResult)

    def test_execution_timing_tracking(self):
        """Test that execution time is tracked properly."""
        provider = TestProvider()

        # Mock a slow scan to test timing
        original_scan = provider.scan
        def slow_scan(target):
            time.sleep(0.1)  # 100ms delay
            return original_scan(target)

        with patch.object(provider, 'scan', side_effect=slow_scan):
            result = provider.scan_with_timing("https://example.com")

        # Should have execution time recorded
        assert hasattr(result, 'execution_time')
        assert result.execution_time >= 0.1

    def test_provider_configuration_access(self):
        """Test provider configuration can be accessed properly."""
        config = {
            "api_key": "test123",
            "endpoint": "https://api.test.com",
            "timeout": 30,
            "custom_setting": "value"
        }
        provider = TestProvider(config=config)

        # Configuration should be accessible
        assert provider.config.api_key == "test123"
        assert provider.config.endpoint == "https://api.test.com"
        assert provider.config.timeout == 30
        assert provider.config.custom_setting == "value"

        # Should handle missing keys gracefully
        assert getattr(provider.config, 'missing_key', None) is None

    def test_provider_error_result_creation(self):
        """Test provider can create error results properly."""
        provider = TestProvider()

        # Test various error scenarios
        error_scenarios = [
            ("Network timeout", "Connection timed out after 30 seconds"),
            ("API error", "HTTP 429 - Rate limit exceeded"),
            ("Invalid response", "Response format invalid"),
            ("Missing data", "Required field 'result' not found")
        ]

        for error_type, error_msg in error_scenarios:
            result = provider._create_error_result("https://test.com", error_msg)

            assert result.threat_level == ThreatLevel.ERROR
            assert result.is_threat == False
            assert result.details["error"] == error_msg

    def test_result_serialization_compatibility(self):
        """Test that results can be serialized properly."""
        provider = TestProvider()
        target = "https://example.com"

        # Test different result types
        safe_result = provider._create_safe_result(target, {"status": "clean"})
        threat_result = provider._create_threat_result(target, ThreatLevel.MALICIOUS, {"malware": True})
        error_result = provider._create_error_result(target, "Test error")

        results = [safe_result, threat_result, error_result]

        for result in results:
            # Should be able to access all required fields
            assert hasattr(result, 'provider')
            assert hasattr(result, 'target')
            assert hasattr(result, 'is_threat')
            assert hasattr(result, 'threat_level')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'details')

            # Should be serializable to dict
            result_dict = {
                "provider": result.provider,
                "target": result.target,
                "is_threat": result.is_threat,
                "threat_level": result.threat_level.value,
                "confidence": result.confidence,
                "details": result.details
            }

            assert isinstance(result_dict, dict)
            assert result_dict["provider"] == "test_provider"

    def test_provider_inheritance_requirements(self):
        """Test that provider properly inherits from BaseProvider."""
        provider = TestProvider()

        # Should be instance of BaseProvider
        assert isinstance(provider, BaseProvider)

        # Should have all required methods
        required_methods = ['scan', 'is_available']
        for method_name in required_methods:
            assert hasattr(provider, method_name)
            assert callable(getattr(provider, method_name))

    def test_provider_with_missing_config(self):
        """Test provider behavior with missing or invalid configuration."""
        # Test with None config
        provider = TestProvider(config=None)
        assert provider.provider_name == "test_provider"
        assert hasattr(provider, 'config')

        # Test with empty config
        provider_empty = TestProvider(config={})
        assert provider_empty.provider_name == "test_provider"
        assert hasattr(provider_empty, 'config')

    @patch('url_checker_tools.config.logging_config.get_logger')
    def test_logging_functionality(self, mock_get_logger):
        """Test that logging works correctly."""
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger

        provider = TestProvider()

        # Logger should be set up
        mock_get_logger.assert_called()

        # Should be able to log messages
        provider.logger.info("Test message")
        mock_logger.info.assert_called_with("Test message")

    def test_provider_network_integration(self):
        """Test provider integration with HTTP client."""
        provider = TestProvider()

        # HTTP client should be properly configured
        assert provider.http.provider_name == provider.provider_name

        # Should have access to HTTP methods
        http_methods = ['get', 'post']
        for method in http_methods:
            assert hasattr(provider.http, method)
            assert callable(getattr(provider.http, method))

    def test_concurrent_provider_usage(self):
        """Test provider can handle concurrent usage safely."""
        import threading

        provider = TestProvider()
        results = []
        errors = []

        def scan_target(target_num):
            try:
                result = provider.scan(f"https://example{target_num}.com")
                results.append(result)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=scan_target, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Should have successful results and no errors
        assert len(results) == 5
        assert len(errors) == 0

        # All results should be valid
        for result in results:
            assert isinstance(result, ProviderResult)
            assert result.provider == "test_provider"
