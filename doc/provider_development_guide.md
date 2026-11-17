# Provider Development Guide

This guide explains how to add new threat intelligence providers to the URL Checker system.

## Overview

The URL Checker uses a pluggable provider architecture that makes adding new threat intelligence sources easy and scalable. Each provider is a self-contained Python module that implements the `ThreatProvider` interface.

## Quick Start

### 1. Copy the Template

```bash
cp src/url_checker_tools/providers/_template.py src/url_checker_tools/providers/your_provider.py
```

### 2. Replace Placeholders

Edit the new file and replace all `[TEMPLATE]` and `[template]` placeholders with your provider's information:

- `[TEMPLATE]Provider` → `YourProviderProvider`
- `[TEMPLATE]` → `Your Provider Name`
- `[template]` → `your_provider`
- API endpoints, configuration, etc.

### 3. Add Provider Type

Add your provider to the `ProviderType` enum in `src/url_checker_tools/threat_result.py`:

```python
class ProviderType(Enum):
    # ... existing providers ...
    YOUR_PROVIDER = "your_provider"
```

### 4. Register Provider

Add import to `src/url_checker_tools/providers/registry.py` in the `auto_discover_providers()` method:

```python
provider_modules = [
    # ... existing providers ...
    ("your_provider", "YourProviderProvider"),
]
```

### 5. Test Your Provider

```python
from url_checker_tools.providers.your_provider import YourProviderProvider
from url_checker_tools.providers.base import ProviderConfig

# Configure provider
config = ProviderConfig(
    enabled=True,
    api_key_required=True,
    api_key_account="your_provider"
)

provider = YourProviderProvider(config)
result = provider.scan_url("https://example.com")
print(result)
```

## Provider Architecture

### Base Classes

- **`ThreatProvider`**: Abstract base for all providers
- **`BaseHttpProvider`**: Base for HTTP API-based providers (recommended)

### Key Methods to Implement

#### Required Methods

```python
@property
def name(self) -> str:
    """Unique identifier (lowercase, no spaces)"""

@property
def display_name(self) -> str:
    """Human-readable name"""

@property
def capabilities(self) -> Set[ProviderCapability]:
    """What this provider can do"""

def scan_url(self, url: str) -> ThreatIntelligenceResult:
    """Scan a full URL"""

def scan_domain(self, domain: str) -> ThreatIntelligenceResult:
    """Scan a domain"""
```

#### Optional Methods

```python
def get_config_schema(self) -> dict:
    """Provider-specific configuration options"""

def validate_config(self) -> List[str]:
    """Validate provider configuration"""

@property
def priority(self) -> int:
    """Execution priority (1=highest, 100=lowest)"""
```

## Provider Capabilities

Choose appropriate capabilities for your provider:

```python
class ProviderCapability(Enum):
    URL_SCANNING = "url_scanning"          # Can scan full URLs
    DOMAIN_SCANNING = "domain_scanning"    # Can scan domains only
    FILE_SCANNING = "file_scanning"        # Can scan files
    BULK_SCANNING = "bulk_scanning"        # Supports bulk operations
    REAL_TIME_SCANNING = "real_time_scanning"  # Real-time scanning
```

## Configuration

### Provider Configuration

```python
config = ProviderConfig(
    enabled=True,
    api_key_required=True,           # Does provider need API key?
    api_key_account="provider_name", # Keyring account name
    api_endpoint="https://api.provider.com/v1",
    timeout_seconds=30,
    rate_limit_per_minute=100,       # API rate limits
    rate_limit_per_day=10000,
    custom_config={                  # Provider-specific options
        "include_metadata": True,
        "scan_timeout": 60,
    }
)
```

### API Key Management

The system uses the `keyring` library for secure API key storage:

```bash
# Store API key
python -c "import keyring; keyring.set_password('urlchecker', 'your_provider', 'your-api-key')"

# Keys are automatically retrieved by the provider
```

## Result Creation

Convert your provider's response to a standardized `ThreatIntelligenceResult`:

```python
def _create_result_from_response(self, target: str, response: dict) -> ThreatIntelligenceResult:
    # Parse provider response
    is_malicious = response.get("malicious", False)
    threat_score = response.get("score", 0)

    # Determine standardized status
    if is_malicious:
        status = ThreatStatus.MALICIOUS
    elif threat_score > 50:
        status = ThreatStatus.SUSPICIOUS
    else:
        status = ThreatStatus.CLEAN

    return ThreatIntelligenceResult(
        provider=ProviderType.YOUR_PROVIDER,
        target=target,
        status=status,
        is_threat_detected=is_malicious,
        threat_type="malware" if is_malicious else None,
        confidence=f"score_{threat_score}",
        raw_response=response,
    )
```

## Error Handling

Handle errors gracefully:

```python
def scan_url(self, url: str) -> ThreatIntelligenceResult:
    try:
        response = self._make_api_request(...)
        return self._create_result_from_response(url, response)

    except MissingAPIKeyError:
        raise  # Let registry handle gracefully
    except APIRequestError as e:
        return ThreatIntelligenceResult(
            provider=ProviderType.YOUR_PROVIDER,
            target=url,
            status=ThreatStatus.ERROR,
            error_message=f"API request failed: {e}",
        )
```

## Testing

### Unit Tests

Create `tests/test_your_provider.py`:

```python
import pytest
from url_checker_tools.providers.your_provider import YourProviderProvider
from url_checker_tools.providers.base import ProviderConfig

def test_provider_initialization():
    provider = YourProviderProvider()
    assert provider.name == "your_provider"
    assert provider.display_name == "Your Provider"

def test_provider_scan_url():
    config = ProviderConfig(enabled=True)
    provider = YourProviderProvider(config)

    # Mock API response
    with patch.object(provider, '_make_api_request') as mock_request:
        mock_request.return_value = {"malicious": False, "score": 25}
        result = provider.scan_url("https://example.com")

        assert result.status == ThreatStatus.CLEAN
        assert not result.is_threat_detected
```

### Integration Tests

Test with the full system:

```python
from url_checker_tools.providers.manager import ProviderManager

def test_provider_integration():
    manager = ProviderManager()

    # Configure your provider
    from url_checker_tools.providers.base import ProviderConfig
    config = ProviderConfig(enabled=True, api_key_required=False)

    provider = manager.registry.create_provider("your_provider", config)
    manager.registry.register_provider(provider)

    results = manager.scan_target("example.com", enabled_providers=["your_provider"])
    assert len(results) == 1
```

## Best Practices

### 1. Performance
- Use async/await for HTTP requests when possible
- Implement rate limiting
- Cache results when appropriate
- Set reasonable timeouts

### 2. Reliability
- Handle API errors gracefully
- Provide meaningful error messages
- Implement retry logic for transient failures
- Validate API responses

### 3. Security
- Never log API keys
- Validate all input parameters
- Use HTTPS for all API calls
- Implement proper authentication

### 4. Usability
- Provide clear configuration documentation
- Include helpful error messages
- Support both URL and domain scanning when possible
- Follow consistent naming conventions

## Example Providers

Study existing providers for reference:

- **`whois.py`**: Simple, no API key required
- **`virustotal.py`**: Complex API with authentication
- **`google_sb.py`**: URL-only scanning with rate limits
- **`yara.py`**: Content-based scanning

## CLI Integration

Once your provider is implemented, it automatically works with the modern CLI:

```bash
# Use specific providers
python check_url_modern.py --providers your_provider,virustotal example.com

# Use all available providers
python check_url_modern.py --all-providers example.com

# List all providers
python check_url_modern.py --list-providers
```

## Contributing

When contributing a new provider:

1. Follow the template structure
2. Add comprehensive tests
3. Update documentation
4. Consider rate limits and API costs
5. Ensure backward compatibility

## Need Help?

- Check existing provider implementations
- Review the base class documentation
- Test with the provider template
- Ask questions in issues/discussions
