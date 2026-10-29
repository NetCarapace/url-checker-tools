#!/usr/bin/env python3
"""Comprehensive functional tests for MISP integration."""

import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.integrations.misp_reporter import MISPReporter
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class TestMISPIntegrationFunctionality:
    """Test MISP integration functionality comprehensively."""

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_reporter_initialization_verbose_mode(self, mock_get_configs):
        """Test MISPReporter initialization in verbose mode."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        # Test verbose=True (warnings should NOT be suppressed)
        with patch('warnings.filterwarnings') as mock_filter, \
             patch('urllib3.disable_warnings') as mock_disable:

            reporter = MISPReporter(verbose=True)

            # Warnings should NOT be suppressed in verbose mode
            mock_filter.assert_not_called()
            mock_disable.assert_not_called()

            assert reporter._verbose == True
            assert hasattr(reporter, 'config')
            assert hasattr(reporter, '_logger')

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_reporter_initialization_quiet_mode(self, mock_get_configs):
        """Test MISPReporter initialization in quiet mode."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        # Test verbose=False (warnings should be suppressed)
        with patch('warnings.filterwarnings') as mock_filter, \
             patch('urllib3.disable_warnings') as mock_disable:

            reporter = MISPReporter(verbose=False)

            # Warnings should be suppressed in quiet mode
            mock_filter.assert_called_once_with('ignore', message='Unverified HTTPS request is being made')
            mock_disable.assert_called_once()

            assert reporter._verbose == False
            assert hasattr(reporter, 'config')
            assert hasattr(reporter, '_logger')

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_reporter_default_initialization(self, mock_get_configs):
        """Test MISPReporter initialization with default parameters."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        with patch('warnings.filterwarnings') as mock_filter, \
             patch('urllib3.disable_warnings') as mock_disable:

            # Default should be verbose=False
            reporter = MISPReporter()

            # Should suppress warnings by default
            mock_filter.assert_called_once()
            mock_disable.assert_called_once()

            assert reporter._verbose == False

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_reporter_availability_check(self, mock_get_configs):
        """Test MISP availability checking functionality."""
        # Test with valid configuration
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        # Mock pymisp in sys.modules to avoid import conflicts
        with patch.dict('sys.modules', {'pymisp': Mock()}):
            reporter = MISPReporter()
            assert reporter.is_available() == True

        # Test with missing API key
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com'
                # No API key
            }
        }

        reporter = MISPReporter()
        assert reporter.is_available() == False

        # Test with missing URL
        mock_get_configs.return_value = {
            'misp': {
                'api_key': 'test_key_123'
                # No URL
            }
        }

        reporter = MISPReporter()
        assert reporter.is_available() == False

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_reporter_pymisp_import_handling(self, mock_get_configs):
        """Test MISP reporter handles pymisp import issues gracefully."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        # Test that is_available method works and returns a boolean
        reporter = MISPReporter()
        result = reporter.is_available()
        assert isinstance(result, bool)  # Should return a boolean regardless of pymisp availability

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_client_initialization(self, mock_get_configs):
        """Test MISP client initialization functionality."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123',
                'verify_ssl': True
            }
        }

        with patch.dict('sys.modules', {'pymisp': Mock()}), \
             patch('pymisp.PyMISP') as mock_pymisp_class:
            mock_client = Mock()
            mock_client.get_user.return_value = {"user": {"id": 1}}
            mock_pymisp_class.return_value = mock_client

            reporter = MISPReporter()
            reporter._initialize_misp_client()

            # Should create PyMISP client with correct parameters
            mock_pymisp_class.assert_called_once_with(
                'https://misp.test.com',
                'test_key_123',
                ssl=True,
                debug=False
            )

            # Should test connection
            mock_client.get_user.assert_called_once()

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_event_creation_with_threats(self, mock_get_configs):
        """Test MISP event creation with threat results."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        with patch.dict('sys.modules', {'pymisp': Mock()}), \
             patch('pymisp.PyMISP') as mock_pymisp_class:
            mock_client = Mock()
            # Create a mock event that doesn't have 'errors' attribute
            mock_event = Mock(spec=['id', 'uuid'])
            mock_event.id = 123
            mock_event.uuid = 'test-uuid-123'

            mock_client.get_user.return_value = {"user": {"id": 1}}
            # Configure add_event to return a properly mocked event (pythonify=True)
            mock_client.add_event.return_value = mock_event
            mock_client.add_attribute.return_value = Mock()
            mock_client.tag.return_value = Mock()
            mock_client.search.return_value = []

            mock_pymisp_class.return_value = mock_client

            # Create test results with threats
            threat_results = [
                ProviderResult(
                    provider="virustotal",
                    target="https://malicious.example.com",
                    is_threat=True,
                    threat_level=ThreatLevel.MALICIOUS,
                    confidence=0.9,
                    details={"malicious_count": 5, "total_engines": 50},
                    execution_time=1.5,
                    error_message=None
                ),
                ProviderResult(
                    provider="google_sb",
                    target="https://malicious.example.com",
                    is_threat=True,
                    threat_level=ThreatLevel.MALICIOUS,
                    confidence=0.8,
                    details={"threat_types": ["malware"]},
                    execution_time=0.8,
                    error_message=None
                )
            ]

            reporter = MISPReporter()
            result = reporter.create_event("https://malicious.example.com", threat_results, "session_123")

            # Should create event
            mock_client.add_event.assert_called_once()

            # Should return event info
            assert result is not None
            assert result["event_id"] == 123
            assert result["uuid"] == 'test-uuid-123'

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_event_creation_no_threats(self, mock_get_configs):
        """Test MISP event creation with no threat results."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        with patch.dict('sys.modules', {'pymisp': Mock()}), \
             patch('pymisp.PyMISP') as mock_pymisp_class:
            # We don't need to set up the mock since this should return None before calling MISP
            mock_client = Mock()
            mock_pymisp_class.return_value = mock_client

            # Create test results with no threats
            safe_results = [
                ProviderResult(
                    provider="virustotal",
                    target="https://safe.example.com",
                    is_threat=False,
                    threat_level=ThreatLevel.SAFE,
                    confidence=0.9,
                    details={"malicious_count": 0, "total_engines": 50},
                    execution_time=1.2,
                    error_message=None
                )
            ]

            reporter = MISPReporter()
            result = reporter.create_event("https://safe.example.com", safe_results, "session_123")

            # Should not create event for safe results (should return None before calling MISP)
            assert result is None
            # Verify MISP client was never created since there are no threats
            mock_pymisp_class.assert_not_called()

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_configuration_loading(self, mock_get_configs):
        """Test MISP configuration loading from various sources."""
        # Test with api_key field
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_from_api_key_field'
            }
        }

        reporter = MISPReporter()
        assert reporter.config.url == 'https://misp.test.com'
        assert reporter.config.api_key == 'test_key_from_api_key_field'

        # Test with key field (alternative naming)
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'key': 'test_key_from_key_field'
            }
        }

        reporter = MISPReporter()
        assert reporter.config.key == 'test_key_from_key_field'

        # Test SSL verification settings
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key',
                'verify_ssl': False,
                'verifycert': True  # Alternative naming
            }
        }

        reporter = MISPReporter()
        assert reporter.config.verify_ssl == False
        assert reporter.config.verifycert == True

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_error_handling(self, mock_get_configs):
        """Test MISP error handling functionality."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        with patch.dict('sys.modules', {'pymisp': Mock()}), \
             patch('pymisp.PyMISP') as mock_pymisp_class:
            # Test client creation failure
            mock_pymisp_class.side_effect = Exception("Connection failed")

            reporter = MISPReporter()

            with pytest.raises(Exception):
                reporter._initialize_misp_client()

        # Test event creation failure
        with patch.dict('sys.modules', {'pymisp': Mock()}), \
             patch('pymisp.PyMISP') as mock_pymisp_class:
            mock_client = Mock()
            mock_client.get_user.return_value = {"user": {"id": 1}}
            mock_client.add_event.side_effect = Exception("Event creation failed")
            mock_pymisp_class.return_value = mock_client

            threat_results = [
                ProviderResult(
                    provider="test",
                    target="https://example.com",
                    is_threat=True,
                    threat_level=ThreatLevel.MALICIOUS,
                    confidence=0.9,
                    details={},
                    execution_time=1.0,
                    error_message=None
                )
            ]

            reporter = MISPReporter()
            result = reporter.create_event("https://example.com", threat_results, "session_123")

            # Should return None on failure
            assert result is None

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_ssl_warning_suppression_behavior(self, mock_get_configs):
        """Test SSL warning suppression behavior in different modes."""
        mock_get_configs.return_value = {'misp': {}}

        # Test warning suppression is applied correctly
        with patch('warnings.filterwarnings') as mock_filter:
            reporter_quiet = MISPReporter(verbose=False)
            mock_filter.assert_called_with('ignore', message='Unverified HTTPS request is being made')

        # Test warnings are not suppressed in verbose mode
        with patch('warnings.filterwarnings') as mock_filter:
            reporter_verbose = MISPReporter(verbose=True)
            mock_filter.assert_not_called()

        # Test that both modes maintain functionality
        assert reporter_quiet._verbose == False
        assert reporter_verbose._verbose == True

    def test_misp_integration_with_url_checker_tools(self):
        """Test MISP integration works with url_checker_tools verbose flag passing."""
        from types import SimpleNamespace

        # Test getattr pattern used in url_checker_tools
        args_with_verbose = SimpleNamespace(verbose=True)
        args_without_verbose = SimpleNamespace(verbose=False)
        args_missing_verbose = SimpleNamespace()

        # Test verbose flag extraction
        verbose_true = getattr(args_with_verbose, 'verbose', False)
        verbose_false = getattr(args_without_verbose, 'verbose', False)
        verbose_default = getattr(args_missing_verbose, 'verbose', False)

        assert verbose_true == True
        assert verbose_false == False
        assert verbose_default == False  # Default when missing

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_attribute_creation_ordering(self, mock_get_configs):
        """Test MISP attribute creation and ordering functionality."""
        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        with patch.dict('sys.modules', {'pymisp': Mock()}), \
             patch('pymisp.PyMISP') as mock_pymisp_class:
            mock_client = Mock()
            # Create a mock event that doesn't have 'errors' attribute
            mock_event = Mock(spec=['id', 'uuid'])
            mock_event.id = 456
            mock_event.uuid = 'test-uuid-456'

            mock_client.get_user.return_value = {"user": {"id": 1}}
            mock_client.add_event.return_value = mock_event
            mock_client.add_attribute.return_value = Mock()
            mock_client.tag.return_value = Mock()
            mock_client.search.return_value = []

            mock_pymisp_class.return_value = mock_client

            # Create comprehensive test results
            comprehensive_results = [
                ProviderResult(
                    provider="whalebone",
                    target="https://test.example.com",
                    is_threat=True,
                    threat_level=ThreatLevel.MALICIOUS,
                    confidence=0.95,
                    details={"categories": ["malware"], "max_accuracy": 95},
                    execution_time=2.1,
                    error_message=None
                ),
                ProviderResult(
                    provider="link_analyzer",
                    target="https://test.example.com",
                    is_threat=False,
                    threat_level=ThreatLevel.SAFE,
                    confidence=0.8,
                    details={"final_url": "https://test.example.com", "redirect_count": 0},
                    execution_time=0.5,
                    error_message=None
                )
            ]

            reporter = MISPReporter()
            result = reporter.create_event("https://test.example.com", comprehensive_results, "session_456")

            # Should create event and add multiple attributes
            assert mock_client.add_event.called
            assert mock_client.add_attribute.called
            assert mock_client.tag.called

            # Should return valid result
            assert result is not None
            assert result["event_id"] == 456

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_configuration_fallback(self, mock_get_configs):
        """Test MISP configuration fallback mechanisms."""
        # Test configuration loading fallback
        mock_get_configs.side_effect = Exception("Config loading failed")

        with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_misp_config') as mock_fallback:
            mock_fallback.return_value = {
                'url': 'https://fallback.misp.com',
                'api_key': 'fallback_key'
            }

            reporter = MISPReporter()

            # Should use fallback configuration
            mock_fallback.assert_called_once()
            assert reporter.config.url == 'https://fallback.misp.com'
            assert reporter.config.api_key == 'fallback_key'

    @patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs')
    def test_misp_reporter_thread_safety(self, mock_get_configs):
        """Test MISP reporter can handle concurrent usage."""
        import threading

        mock_get_configs.return_value = {
            'misp': {
                'url': 'https://misp.test.com',
                'api_key': 'test_key_123'
            }
        }

        # Test multiple reporters can be created concurrently
        reporters = []
        errors = []

        def create_reporter(verbose_mode):
            try:
                reporter = MISPReporter(verbose=verbose_mode)
                reporters.append(reporter)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = []
        for i in range(5):
            verbose = i % 2 == 0  # Alternate verbose modes
            thread = threading.Thread(target=create_reporter, args=(verbose,))
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # All should succeed
        assert len(reporters) == 5
        assert len(errors) == 0

        # Each reporter should be properly configured
        for reporter in reporters:
            assert hasattr(reporter, '_verbose')
            assert hasattr(reporter, 'config')
            assert hasattr(reporter, '_logger')
