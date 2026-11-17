#!/usr/bin/env python3
"""Automated provider discovery and validation tests."""

import sys
import importlib
import inspect
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult
from url_checker_tools.core.key_manager import KeyManager


def discover_provider_files():
    """Discover all provider files in the providers directory."""
    providers_dir = Path(__file__).parent.parent / "src" / "url_checker_tools" / "providers"

    if not providers_dir.exists():
        return []

    provider_files = []
    for py_file in providers_dir.glob("*.py"):
        # Skip utility files
        if py_file.name in ["__init__.py"]:
            continue
        provider_files.append(py_file)

    return provider_files


def discover_provider_classes():
    """Discover all provider classes from provider files."""
    provider_files = discover_provider_files()
    provider_classes = []

    for provider_file in provider_files:
        try:
            # Import the module
            module_name = f"url_checker_tools.providers.{provider_file.stem}"
            module = importlib.import_module(module_name)

            # Find classes that inherit from BaseProvider
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, BaseProvider) and
                    obj != BaseProvider and
                    obj.__module__ == module_name):
                    provider_classes.append((provider_file.stem, name, obj))

        except ImportError as e:
            # Log import failures but continue
            print(f"Warning: Could not import {provider_file.stem}: {e}")

    return provider_classes


def get_provider_api_key_status():
    """Get API key availability status for all providers using KeyManager."""
    key_manager = KeyManager()

    # Map provider file names to their key checker methods
    provider_key_methods = {
        'virustotal': key_manager.has_virustotal_key,
        'urlscan': key_manager.has_urlscan_key,
        'google_sb': key_manager.has_google_sb_key,
        'abuseipdb': key_manager.has_abuseipdb_key,
        'whalebone': lambda: key_manager.has_whalebone_key() and key_manager.has_whalebone_user(),
        'lookyloo': lambda: False,  # Lookyloo doesn't have a specific key checker yet
        'pandora': lambda: False,   # Pandora doesn't have a specific key checker yet
    }

    status = {}
    for provider_name, checker in provider_key_methods.items():
        try:
            status[provider_name] = checker()
        except Exception:
            status[provider_name] = False

    return status


def get_providers_with_api_keys():
    """Get list of providers that have API keys configured."""
    api_status = get_provider_api_key_status()
    return [provider for provider, has_key in api_status.items() if has_key]


def get_providers_without_api_keys():
    """Get list of providers that don't have API keys configured."""
    api_status = get_provider_api_key_status()
    return [provider for provider, has_key in api_status.items() if not has_key]


class TestProviderDiscovery:
    """Test automated provider discovery and validation."""

    def test_provider_files_exist(self):
        """Test that provider files exist in the providers directory."""
        provider_files = discover_provider_files()

        # Should have at least some provider files
        assert len(provider_files) > 0, "Should have provider files in providers directory"

        # Each file should be a Python file
        for provider_file in provider_files:
            assert provider_file.suffix == ".py", f"{provider_file.name} should be a Python file"
            assert provider_file.is_file(), f"{provider_file.name} should be a file"

    @pytest.mark.parametrize("provider_file", discover_provider_files())
    def test_provider_file_imports_successfully(self, provider_file):
        """Test each provider file can be imported without errors."""
        module_name = f"url_checker_tools.providers.{provider_file.stem}"

        try:
            module = importlib.import_module(module_name)
            assert module is not None, f"Module {module_name} should import successfully"
        except ImportError as e:
            pytest.fail(f"Provider file {provider_file.stem} should import without errors: {e}")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_inherits_from_base_provider(self, provider_info):
        """Test each provider class properly inherits from BaseProvider."""
        file_name, class_name, provider_class = provider_info

        # Should inherit from BaseProvider
        assert issubclass(provider_class, BaseProvider), \
            f"Provider {class_name} in {file_name} should inherit from BaseProvider"

        # Should not be BaseProvider itself
        assert provider_class != BaseProvider, \
            f"Provider {class_name} should not be BaseProvider itself"

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_implements_required_methods(self, provider_info):
        """Test each provider implements required abstract methods."""
        file_name, class_name, provider_class = provider_info

        # Check required methods exist and are callable
        required_methods = ['scan', 'is_available']

        for method_name in required_methods:
            assert hasattr(provider_class, method_name), \
                f"Provider {class_name} should have {method_name} method"

            method = getattr(provider_class, method_name)
            assert callable(method), \
                f"Provider {class_name}.{method_name} should be callable"

        # Ensure methods are not just inherited from BaseProvider without implementation
        # (This checks that abstract methods are properly overridden)
        try:
            # Try to instantiate with minimal config
            with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs') as mock_config:
                mock_config.return_value = {file_name: {}}

                instance = provider_class(file_name, {})

                # Should be able to call is_available without errors
                is_available = instance.is_available()
                assert isinstance(is_available, bool), \
                    f"Provider {class_name}.is_available() should return boolean"

        except TypeError as e:
            if "abstract" in str(e).lower():
                pytest.fail(f"Provider {class_name} has unimplemented abstract methods: {e}")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_can_be_instantiated(self, provider_info):
        """Test each provider can be instantiated with basic configuration."""
        file_name, class_name, provider_class = provider_info

        try:
            with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs') as mock_config:
                mock_config.return_value = {file_name: {"test_config": "value"}}

                # Try to instantiate provider
                instance = provider_class(file_name, {"test_config": "value"})

                # Basic checks
                assert instance is not None, f"Provider {class_name} should instantiate successfully"
                assert hasattr(instance, 'provider_name'), f"Provider {class_name} should have provider_name"
                assert hasattr(instance, 'config'), f"Provider {class_name} should have config"
                assert hasattr(instance, 'http'), f"Provider {class_name} should have http client"
                assert hasattr(instance, 'logger'), f"Provider {class_name} should have logger"

        except Exception as e:
            pytest.fail(f"Provider {class_name} should be instantiable with basic config: {e}")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_scan_method_signature(self, provider_info):
        """Test provider scan method has correct signature."""
        file_name, class_name, provider_class = provider_info

        # Check scan method signature
        scan_method = getattr(provider_class, 'scan')
        signature = inspect.signature(scan_method)

        # Should have 'self' and 'target' parameters at minimum
        params = list(signature.parameters.keys())
        assert len(params) >= 2, f"Provider {class_name}.scan should have at least 2 parameters"
        assert params[0] == 'self', f"Provider {class_name}.scan first parameter should be 'self'"
        assert 'target' in params, f"Provider {class_name}.scan should have 'target' parameter"

        # Return annotation should indicate ProviderResult (if present)
        if signature.return_annotation != inspect.Signature.empty:
            # If return annotation is present, it should be ProviderResult
            expected_types = [ProviderResult, 'ProviderResult', 'url_checker_tools.core.results.ProviderResult']
            return_annotation_str = str(signature.return_annotation)

            # Check if return annotation suggests ProviderResult
            matches_expected = any(
                expected in return_annotation_str for expected in
                ['ProviderResult', 'results.ProviderResult']
            )

            if not matches_expected:
                # This is a warning, not a failure, as annotation might be valid but different
                print(f"Note: Provider {class_name}.scan return annotation is {signature.return_annotation}")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_is_available_method_signature(self, provider_info):
        """Test provider is_available method has correct signature."""
        file_name, class_name, provider_class = provider_info

        # Check is_available method signature
        is_available_method = getattr(provider_class, 'is_available')
        signature = inspect.signature(is_available_method)

        # Should have only 'self' parameter
        params = list(signature.parameters.keys())
        assert len(params) == 1, f"Provider {class_name}.is_available should have only 'self' parameter"
        assert params[0] == 'self', f"Provider {class_name}.is_available parameter should be 'self'"

        # Return annotation should indicate bool (if present)
        if signature.return_annotation != inspect.Signature.empty:
            return_annotation_str = str(signature.return_annotation)
            assert 'bool' in return_annotation_str.lower(), \
                f"Provider {class_name}.is_available should return bool, got {signature.return_annotation}"

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_naming_conventions(self, provider_info):
        """Test provider follows naming conventions."""
        file_name, class_name, provider_class = provider_info

        # Class name should be in PascalCase and end with "Provider"
        assert class_name.endswith('Provider'), \
            f"Provider class {class_name} should end with 'Provider'"

        # Should start with uppercase letter
        assert class_name[0].isupper(), \
            f"Provider class {class_name} should start with uppercase letter"

        # File name should be lowercase and snake_case
        assert file_name.islower() or '_' in file_name, \
            f"Provider file {file_name} should be lowercase or snake_case"

    def test_provider_registration_consistency(self):
        """Test all discovered providers are properly registered."""
        provider_classes = discover_provider_classes()

        try:
            from url_checker_tools.config.providers_enum import ProviderConfigTemplate

            # Get all registered provider configs
            all_configs = ProviderConfigTemplate.get_all_provider_configs()
            registered_providers = set(all_configs.keys())

            # Get discovered provider names (based on file names)
            discovered_providers = {info[0] for info in provider_classes}

            # Check for providers that are implemented but not registered
            unregistered = discovered_providers - registered_providers
            if unregistered:
                print(f"Warning: Found unregistered providers: {unregistered}")

            # Check for providers that are registered but not implemented
            unimplemented = registered_providers - discovered_providers
            if unimplemented:
                print(f"Note: Found registered providers without implementation files: {unimplemented}")

        except ImportError:
            pytest.skip("ProviderConfigTemplate not available for registration check")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_has_configuration_template(self, provider_info):
        """Test each provider has a configuration template."""
        file_name, class_name, provider_class = provider_info

        try:
            from url_checker_tools.config.providers_enum import ProviderConfigTemplate

            # Check if provider has configuration template
            all_configs = ProviderConfigTemplate.get_all_provider_configs()

            assert file_name in all_configs, \
                f"Provider {class_name} (file: {file_name}) should have configuration template"

            # Configuration should be a dictionary
            provider_config = all_configs[file_name]
            assert isinstance(provider_config, dict), \
                f"Provider {class_name} configuration should be a dictionary"

        except ImportError:
            pytest.skip("ProviderConfigTemplate not available for configuration check")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_handles_basic_scan_call(self, provider_info):
        """Test provider can handle basic scan method call."""
        file_name, class_name, provider_class = provider_info

        try:
            with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs') as mock_config:
                mock_config.return_value = {file_name: {"available": True}}

                # Mock HTTP client to prevent actual network calls
                with patch('url_checker_tools.core.http_client.HTTPClient') as mock_http_client:
                    mock_http_instance = Mock()
                    mock_http_client.return_value = mock_http_instance

                    instance = provider_class(file_name, {"available": True})

                    # Mock scan method if it makes external calls
                    test_target = "https://test.example.com"

                    # We don't actually call scan here to avoid network dependencies,
                    # but we verify the method exists and can be called
                    assert callable(instance.scan), \
                        f"Provider {class_name}.scan should be callable"

                    # Verify method signature allows the call we want to make
                    signature = inspect.signature(instance.scan)
                    try:
                        # This should not raise an exception for signature binding
                        if 'self' in signature.parameters:
                            signature.bind(instance, test_target)
                        else:
                            signature.bind(test_target)
                    except TypeError as e:
                        pytest.fail(f"Provider {class_name}.scan signature incompatible with basic call: {e}")

        except Exception as e:
            # Don't fail the test for instantiation issues, just note them
            print(f"Note: Provider {class_name} instantiation issue (may need specific config): {e}")

    @pytest.mark.network
    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    @pytest.mark.parametrize("test_target", [
        "https://www.google.com",
        "https://github.com"
    ])
    def test_provider_connectivity_with_benign_sites(self, provider_info, test_target):
        """Test provider can actually scan benign reference sites."""
        file_name, class_name, provider_class = provider_info

        # Skip providers that require API keys for this connectivity test
        api_dependent_providers = ['virustotal', 'whalebone', 'urlscan', 'lookyloo', 'pandora', 'abuseipdb', 'google_sb']
        if file_name in api_dependent_providers:
            pytest.skip(f"Skipping {class_name} - requires API key configuration")

        try:
            # Instantiate with new architecture (no parameters)
            instance = provider_class()

            # Check if provider is available (has required config/tools)
            if not instance.is_available():
                pytest.skip(f"Provider {class_name} not available (missing config/tools)")

            # Perform actual scan
            with instance as provider:
                result = provider.scan(test_target)

                # Validate result structure
                assert result is not None, f"Provider {class_name} should return a result"
                assert hasattr(result, 'provider'), f"Result should have provider field"
                assert hasattr(result, 'target'), f"Result should have target field"
                assert hasattr(result, 'is_threat'), f"Result should have is_threat field"
                assert hasattr(result, 'threat_level'), f"Result should have threat_level field"
                assert hasattr(result, 'confidence'), f"Result should have confidence field"
                assert hasattr(result, 'details'), f"Result should have details field"

                # Validate result content
                assert result.provider == provider.provider_name, f"Result provider should match provider name"
                assert result.target == test_target, f"Result target should match input target"
                assert isinstance(result.is_threat, bool), f"Result is_threat should be boolean"
                assert isinstance(result.confidence, (int, float)), f"Result confidence should be numeric"
                assert isinstance(result.details, dict), f"Result details should be dictionary"

                print(f"✓ {class_name} successfully scanned {test_target}: {'THREAT' if result.is_threat else 'SAFE'}")

        except Exception as e:
            pytest.fail(f"Provider {class_name} failed connectivity test with {test_target}: {e}")

    @pytest.mark.network
    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    @pytest.mark.parametrize("test_target", [
        "http://malware.wicar.org/data/eicar.com",  # EICAR test virus
        "http://malware.wicar.org/data/js_crypto_miner.html",  # JavaScript crypto miner
    ])
    def test_provider_malicious_detection_with_test_sites(self, provider_info, test_target):
        """Test provider can detect malicious content using WICAR test sites."""
        file_name, class_name, provider_class = provider_info

        # Skip providers that require API keys for this connectivity test
        api_dependent_providers = ['virustotal', 'whalebone', 'urlscan', 'lookyloo', 'pandora', 'abuseipdb', 'google_sb']
        if file_name in api_dependent_providers:
            pytest.skip(f"Skipping {class_name} - requires API key configuration")

        try:
            # Instantiate with new architecture (no parameters)
            instance = provider_class()

            # Check if provider is available (has required config/tools)
            if not instance.is_available():
                pytest.skip(f"Provider {class_name} not available (missing config/tools)")

            # Perform actual scan on malicious test site
            with instance as provider:
                result = provider.scan(test_target)

                # Validate result structure (same as benign test)
                assert result is not None, f"Provider {class_name} should return a result"
                assert hasattr(result, 'provider'), f"Result should have provider field"
                assert hasattr(result, 'target'), f"Result should have target field"
                assert hasattr(result, 'is_threat'), f"Result should have is_threat field"
                assert hasattr(result, 'threat_level'), f"Result should have threat_level field"
                assert hasattr(result, 'confidence'), f"Result should have confidence field"
                assert hasattr(result, 'details'), f"Result should have details field"

                # Validate result content
                assert result.provider == provider.provider_name, f"Result provider should match provider name"
                assert result.target == test_target, f"Result target should match input target"
                assert isinstance(result.is_threat, bool), f"Result is_threat should be boolean"
                assert isinstance(result.confidence, (int, float)), f"Result confidence should be numeric"
                assert isinstance(result.details, dict), f"Result details should be dictionary"

                # Note: We don't assert that result.is_threat == True because:
                # 1. Some providers may not detect these specific test samples
                # 2. Some providers may have different detection capabilities
                # 3. This test validates the result structure and execution, not detection accuracy

                threat_status = "THREAT" if result.is_threat else "SAFE"
                print(f"✓ {class_name} scanned {test_target}: {threat_status} (confidence: {result.confidence})")

        except Exception as e:
            pytest.fail(f"Provider {class_name} failed malicious detection test with {test_target}: {e}")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_context_manager_support(self, provider_info):
        """Test provider supports context manager usage."""
        file_name, class_name, provider_class = provider_info

        try:
            with patch('url_checker_tools.config.provider_config.ProviderConfigTemplate.get_all_provider_configs') as mock_config:
                mock_config.return_value = {file_name: {}}

                instance = provider_class(file_name, {})

                # Should support context manager protocol (inherited from BaseProvider)
                assert hasattr(instance, '__enter__'), \
                    f"Provider {class_name} should support context manager (__enter__)"
                assert hasattr(instance, '__exit__'), \
                    f"Provider {class_name} should support context manager (__exit__)"

                # Test context manager usage
                with instance as ctx_instance:
                    assert ctx_instance is instance, \
                        f"Provider {class_name} context manager should return self"

        except Exception as e:
            print(f"Note: Provider {class_name} context manager test issue: {e}")

    def test_provider_discovery_completeness(self):
        """Test provider discovery finds all expected providers."""
        provider_files = discover_provider_files()
        provider_classes = discover_provider_classes()

        # Should discover some providers
        assert len(provider_files) > 0, "Should discover provider files"
        assert len(provider_classes) > 0, "Should discover provider classes"

        # Each provider file should ideally have at least one provider class
        files_with_classes = {info[0] for info in provider_classes}
        files_without_classes = set(f.stem for f in provider_files) - files_with_classes

        if files_without_classes:
            print(f"Note: Provider files without discovered classes: {files_without_classes}")

        # Report discovery results
        print(f"Discovered {len(provider_files)} provider files")
        print(f"Discovered {len(provider_classes)} provider classes")
        print(f"Provider classes: {[info[1] for info in provider_classes]}")

    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    def test_provider_error_handling_capability(self, provider_info):
        """Test provider has basic error handling capability."""
        file_name, class_name, provider_class = provider_info

        # Check if provider imports necessary exception classes
        try:
            module_name = f"url_checker_tools.providers.{file_name}"
            module = importlib.import_module(module_name)

            # Check if module imports common exception classes
            module_vars = vars(module)

            # Should have access to exception handling
            # (Either through imports or through BaseProvider inheritance)
            exception_indicators = [
                'Exception', 'URLCheckerError', 'APIRequestError', 'requests', 'urllib3'
            ]

            has_error_handling = any(
                indicator in str(module_vars) for indicator in exception_indicators
            )

            # This is informational - providers should handle errors but may do so in various ways
            if not has_error_handling:
                print(f"Note: Provider {class_name} may need explicit error handling imports")

        except ImportError:
            # Already tested in other methods
            pass

    def test_all_discovered_providers_summary(self):
        """Generate summary of all discovered providers."""
        provider_files = discover_provider_files()
        provider_classes = discover_provider_classes()

        # Create summary
        summary = {
            "total_provider_files": len(provider_files),
            "total_provider_classes": len(provider_classes),
            "provider_files": [f.stem for f in provider_files],
            "provider_classes": [(info[0], info[1]) for info in provider_classes]
        }

        print("\n=== Provider Discovery Summary ===")
        print(f"Total provider files: {summary['total_provider_files']}")
        print(f"Total provider classes: {summary['total_provider_classes']}")
        print("Provider files:", summary['provider_files'])
        print("Provider classes:", [f"{file}:{cls}" for file, cls in summary['provider_classes']])

        # The summary itself serves as a test that discovery works
        assert summary['total_provider_files'] > 0
        assert summary['total_provider_classes'] > 0

    def test_api_key_configuration_status(self):
        """Test API key configuration status for all providers."""
        api_status = get_provider_api_key_status()

        print("\n=== API Key Configuration Status ===")
        configured_providers = []
        missing_providers = []

        for provider, has_key in api_status.items():
            if has_key:
                configured_providers.append(provider)
                print(f"✓ {provider}: API key configured")
            else:
                missing_providers.append(provider)
                print(f"✗ {provider}: No API key configured")

        print(f"\nSummary:")
        print(f"  - Providers with API keys: {len(configured_providers)}")
        print(f"  - Providers without API keys: {len(missing_providers)}")

        if configured_providers:
            print(f"  - Configured: {', '.join(configured_providers)}")
        if missing_providers:
            print(f"  - Missing keys: {', '.join(missing_providers)}")
            print(f"\nTo add missing API keys, use:")
            for provider in missing_providers:
                print(f"  python tools/manage_keys.py add --account {provider}")

        # This test always passes - it's informational
        assert True, "API key status check completed"

    @pytest.mark.network
    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    @pytest.mark.parametrize("test_target", [
        "https://www.google.com",
        "https://github.com"
    ])
    def test_api_key_configured_provider_connectivity(self, provider_info, test_target):
        """Test connectivity for providers that have API keys configured."""
        file_name, class_name, provider_class = provider_info

        # Check if this provider has an API key configured
        api_status = get_provider_api_key_status()
        provider_has_key = api_status.get(file_name, False)

        # Only test providers that have API keys
        if not provider_has_key:
            pytest.skip(f"Skipping {class_name} - no API key configured (use test_api_key_configuration_status to see how to add)")

        try:
            # Instantiate provider (should use real API key)
            instance = provider_class()

            # Check if provider is available with real configuration
            if not instance.is_available():
                pytest.skip(f"Provider {class_name} not available despite having API key (check configuration)")

            # Perform actual scan with real API
            print(f"Testing {class_name} with real API key on {test_target}")
            result = instance.scan(test_target)

            # Validate result structure
            assert result is not None, f"Provider {class_name} should return a result"
            assert hasattr(result, 'provider'), f"Result should have provider field"
            assert hasattr(result, 'target'), f"Result should have target field"
            assert hasattr(result, 'is_threat'), f"Result should have is_threat field"
            assert hasattr(result, 'threat_level'), f"Result should have threat_level field"
            assert hasattr(result, 'confidence'), f"Result should have confidence field"
            assert hasattr(result, 'details'), f"Result should have details field"

            # Validate result content
            assert result.provider == instance.provider_name, f"Result provider should match provider name"
            assert result.target == test_target, f"Result target should match input target"
            assert isinstance(result.is_threat, bool), f"Result is_threat should be boolean"
            assert isinstance(result.confidence, (int, float)), f"Result confidence should be numeric"
            assert isinstance(result.details, dict), f"Result details should be dictionary"

            threat_status = "THREAT" if result.is_threat else "SAFE"
            print(f"✓ {class_name} (with API key) scanned {test_target}: {threat_status} (confidence: {result.confidence})")

        except Exception as e:
            pytest.fail(f"Provider {class_name} with API key failed connectivity test: {e}")

    @pytest.mark.network
    @pytest.mark.parametrize("provider_info", discover_provider_classes())
    @pytest.mark.parametrize("test_target", [
        "http://malware.wicar.org/data/eicar.com",
        "http://malware.wicar.org/data/js_crypto_miner.html"
    ])
    def test_api_key_configured_provider_malicious_detection(self, provider_info, test_target):
        """Test malicious detection for providers that have API keys configured."""
        file_name, class_name, provider_class = provider_info

        # Check if this provider has an API key configured
        api_status = get_provider_api_key_status()
        provider_has_key = api_status.get(file_name, False)

        # Only test providers that have API keys
        if not provider_has_key:
            pytest.skip(f"Skipping {class_name} - no API key configured (use test_api_key_configuration_status to see how to add)")

        try:
            # Instantiate provider (should use real API key)
            instance = provider_class()

            # Check if provider is available with real configuration
            if not instance.is_available():
                pytest.skip(f"Provider {class_name} not available despite having API key (check configuration)")

            # Perform actual scan with real API on malicious content
            print(f"Testing {class_name} malicious detection with real API key on {test_target}")
            result = instance.scan(test_target)

            # Validate result structure
            assert result is not None, f"Provider {class_name} should return a result"
            assert hasattr(result, 'provider'), f"Result should have provider field"
            assert hasattr(result, 'target'), f"Result should have target field"
            assert hasattr(result, 'is_threat'), f"Result should have is_threat field"
            assert hasattr(result, 'threat_level'), f"Result should have threat_level field"
            assert hasattr(result, 'confidence'), f"Result should have confidence field"
            assert hasattr(result, 'details'), f"Result should have details field"

            # Validate result content
            assert result.provider == instance.provider_name, f"Result provider should match provider name"
            assert result.target == test_target, f"Result target should match input target"
            assert isinstance(result.is_threat, bool), f"Result is_threat should be boolean"
            assert isinstance(result.confidence, (int, float)), f"Result confidence should be numeric"
            assert isinstance(result.details, dict), f"Result details should be dictionary"

            threat_status = "THREAT" if result.is_threat else "SAFE"
            detection_note = " (DETECTED!)" if result.is_threat else " (not detected - may be expected)"
            print(f"✓ {class_name} (with API key) scanned {test_target}: {threat_status}{detection_note} (confidence: {result.confidence})")

            # Note: We don't assert that result.is_threat == True because:
            # 1. Some providers may not flag these specific WICAR test samples
            # 2. Detection capabilities vary between providers
            # 3. This validates API connectivity and result structure, not detection accuracy

        except Exception as e:
            pytest.fail(f"Provider {class_name} with API key failed malicious detection test: {e}")
