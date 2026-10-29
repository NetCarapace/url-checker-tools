# Quick Testing Scripts

This directory contains convenient testing scripts using industry-standard test URLs for security validation.

## Available Scripts

### `run_eicar.sh` - EICAR Test Virus
Tests the system with the EICAR test virus from WICAR (Web EICAR):
```bash
./run_eicar.sh
```
- **URL**: `http://malware.wicar.org/data/eicar.com`
- **Purpose**: Industry standard malware test file
- **Expected Results**: Some providers may detect as malicious (especially API-based ones)

### `run_miner.sh` - JavaScript Crypto Miner
Tests with a JavaScript cryptocurrency miner:
```bash
./run_miner.sh
```
- **URL**: `http://malware.wicar.org/data/js_crypto_miner.html`
- **Purpose**: Active malicious content detection test
- **Expected Results**: YaraProvider should detect as THREAT, VirusTotal and Google Safe Browsing should also detect

## Recent Test Results

### EICAR Test (`run_eicar.sh`)
```
RESULT: SUSPICIOUS (50/100)
✓ whois: safe
✓ link_analyzer: safe
⚠ virustotal: malicious (14/98 vendors)
⚠ google_sb: threat detected
✓ yara: safe
✓ abuseipdb: safe
```

### Crypto Miner Test (`run_miner.sh`)
```
RESULT: MALICIOUS (78/100)
✓ whois: safe
✓ link_analyzer: safe
⚠ virustotal: malicious (10/98 vendors)
⚠ google_sb: threat detected
⚠ yara: threat detected ← Key detection!
✓ abuseipdb: safe
```

## About WICAR Test Sites

WICAR (Web EICAR) provides the web equivalent of EICAR test files:
- **Safe for Testing**: Non-destructive malware samples designed for security testing
- **Industry Standard**: Widely used by security professionals
- **Comprehensive Coverage**: Various types of malicious content (exploits, miners, etc.)
- **API Integration**: Recognized by major threat intelligence providers

## Usage Notes

- Scripts use `--robot` mode for comprehensive provider coverage
- Results include MISP event creation (if configured)
- Session logs are automatically generated in `data/logs/sessions/`
- SSL warnings for MISP localhost connections are expected
- Whalebone errors are expected (requires specific API configuration)

## Integration with Test Suite

These URLs are also used in the automated test suite:
```bash
# Test provider connectivity with malicious detection
pytest tests/test_provider_discovery.py::TestProviderDiscovery::test_provider_malicious_detection_with_test_sites -v
```

This ensures both manual testing and automated testing use the same validated URLs.
