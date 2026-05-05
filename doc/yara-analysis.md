# YARA Analysis Documentation

## Overview
YARA (Yet Another Recursive Acronym) is a pattern-matching engine designed to identify and classify malware samples.
In our URL checker, YARA analyzes downloaded content, HTML structure, JavaScript patterns, and redirect behavior
to detect threats and suspicious activities.

## Disclaimer
The YARA scanner performs local analysis, which requires downloading potentially malicious content from submitted URLs.
It is strongly recommended to run this scanner only in sandboxed or bastion environments, and not directly alongside
production or user‑facing systems.

## YARA Rule Structure

### Rule Components
```yara
rule SuspiciousRedirect
{
    meta:
        description = "Detects suspicious redirect patterns"
        author = "Threat Research Team"
        reference = "https://example.com/threat-research"

    strings:
        $redirect1 = "window.location.href" nocase
        $redirect2 = "document.location" nocase
        $redirect3 = "meta http-equiv=\"refresh\"" nocase

    condition:
        any of ($redirect*) and filesize < 10KB
}
```

### Rule Categories
- **Malicious Redirects**: JavaScript and meta refresh redirects
- **Phishing Patterns**: Login form mimicry, brand impersonation
- **Malware Indicators**: Exploit kit signatures, payload markers
- **Suspicious Content**: Base64 encoding, obfuscation patterns
- **Infrastructure**: C2 communication patterns, domain generation

## Analysis Process

### Content Acquisition
```python
def analyze_url_with_yara(url):
    # Download page content
    content = download_url_content(url)

    # Extract redirect chain
    redirect_chain = extract_redirect_chain(url)

    # Prepare analysis payload
    analysis_data = {
        "content": content,
        "redirect_chain": redirect_chain,
        "content_type": detect_content_type(content),
        "size": len(content)
    }

    return run_yara_analysis(analysis_data)
```

### Redirect Chain Analysis
```json
{
  "redirect_analysis": {
    "total_hops": 3,
    "redirect_chain": [
      "http://example.com",
      "https://example.com",
      "https://www.example.com"
    ],
    "final_url": "https://www.example.com",
    "suspicious_patterns": [],
    "threat_indicators": []
  }
}
```

## Match Result Structure

### YARA Match Format
```json
{
  "matches": [
    {
      "rule_name": "SuspiciousJavaScript",
      "namespace": "malware",
      "tags": ["javascript", "obfuscation"],
      "meta": {
        "description": "Detects obfuscated JavaScript",
        "severity": "medium",
        "category": "suspicious_code"
      },
      "strings": [
        {
          "identifier": "$obfuscated_js",
          "instances": [
            {
              "offset": 1234,
              "matched_content": "eval(unescape(...",
              "context": "...document.write(eval(unescape(..."
            }
          ]
        }
      ]
    }
  ]
}
```

### Enhanced Match Information
```json
{
  "num_matches": 3,
  "status": "matched",
  "scan_duration": 0.045,
  "content_analyzed": {
    "size": 45678,
    "type": "text/html",
    "encoding": "utf-8"
  }
}
```

## Threat Status Classification

### Status Determination Logic
```python
def determine_yara_status(matches, redirect_analysis):
    num_matches = len(matches)
    redirect_status = redirect_analysis.get("status", "clean")

    if redirect_status == "suspicious_redirects":
        return "suspicious", True
    elif redirect_status == "matched_with_suspicious_redirects":
        return "malicious", True
    elif num_matches > 0:
        return "malicious", True
    else:
        return "clean", False
```

### Status Categories
| Status                              | Condition                           | Threat Level  |
|-------------------------------------|-------------------------------------|---------------|
| `clean`                             | No matches, no suspicious redirects | Safe          |
| `suspicious`                        | Suspicious redirect patterns only   | Medium Risk   |
| `matched`                           | YARA rules matched                  | High Risk     |
| `matched_with_suspicious_redirects` | Both matches and redirect issues    | Critical Risk |
| `error`                             | Analysis failed                     | Unknown       |

## Redirect Pattern Analysis

### Suspicious Redirect Detection
```python
def analyze_redirect_patterns(redirect_chain):
    patterns = []
    threat_indicators = []

    # Check for excessive redirects
    if len(redirect_chain) > 5:
        patterns.append("excessive_redirects")
        threat_indicators.append("redirect_chaining")

    # Check for cross-domain redirects
    domains = [extract_domain(url) for url in redirect_chain]
    unique_domains = set(domains)

    if len(unique_domains) > 3:
        patterns.append("cross_domain_redirects")
        threat_indicators.append("domain_hopping")

    # Check for protocol downgrades
    for i, url in enumerate(redirect_chain[:-1]):
        if url.startswith("https://") and redirect_chain[i+1].startswith("http://"):
            patterns.append("security_downgrade")
            threat_indicators.append("https_downgrade")

    return patterns, threat_indicators
```

### Redirect Chain Validation
```json
{
  "redirect_validation": {
    "chain_length": 3,
    "unique_domains": 1,
    "protocol_changes": ["http->https"],
    "suspicious_tlds": [],
    "url_shorteners": 0,
    "legitimate_pattern": true
  }
}
```

## Rule Categories and Patterns

### Malicious Redirect Rules
```yara
rule MaliciousMetaRedirect
{
    meta:
        description = "Fast meta refresh redirect"
        category = "redirect"

    strings:
        $meta_refresh = /<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][0-5]/ nocase

    condition:
        $meta_refresh
}
```

### Phishing Detection Rules
```yara
rule PhishingLoginForm
{
    meta:
        description = "Suspicious login form patterns"
        category = "phishing"

    strings:
        $login1 = "password" nocase
        $login2 = "username" nocase
        $login3 = "email" nocase
        $suspicious1 = "verify" nocase
        $suspicious2 = "suspended" nocase

    condition:
        2 of ($login*) and any of ($suspicious*)
}
```

### JavaScript Obfuscation Rules
```yara
rule ObfuscatedJavaScript
{
    meta:
        description = "Obfuscated JavaScript patterns"
        category = "malicious_code"

    strings:
        $obfus1 = "eval(" nocase
        $obfus2 = "unescape(" nocase
        $obfus3 = "fromCharCode" nocase
        $obfus4 = /[a-zA-Z]{1,2}=["'][^"']{200,}["']/ // Long encoded strings

    condition:
        2 of them
}
```

## Integration with Threat Result System

### Result Creation
```python
def create_yara_threat_result(target, scan_response):
    scan_status = scan_response.get("status", "unknown")
    num_matches = scan_response.get("num_matches", 0)

    threat_detected = num_matches > 0

    # Enhanced status handling for redirect analysis
    if scan_status == "suspicious_redirects":
        status = ThreatStatus.SUSPICIOUS
        threat_detected = True
    elif scan_status == "matched_with_suspicious_redirects":
        status = ThreatStatus.MALICIOUS
        threat_detected = True
    else:
        status = ThreatStatus.MALICIOUS if threat_detected else ThreatStatus.CLEAN

    return ThreatIntelligenceResult(
        provider=ProviderType.YARA,
        target=target,
        status=status,
        is_threat_detected=threat_detected,
        threat_type=build_threat_type_description(scan_response),
        confidence=build_confidence_string(scan_response),
        raw_response=scan_response
    )
```

### Threat Type Description
```python
def build_threat_type_description(scan_response):
    threat_parts = []
    num_matches = scan_response.get("num_matches", 0)

    if num_matches > 0:
        matches = scan_response.get("matches", [])
        threat_parts.append(f"YARA matches: {len(matches)} rules")

    # Add redirect analysis information
    redirect_analysis = scan_response.get("redirect_analysis", {})
    if redirect_analysis:
        redirect_hops = redirect_analysis.get("total_hops", 0)
        suspicious_patterns = redirect_analysis.get("suspicious_patterns", [])
        threat_indicators = redirect_analysis.get("threat_indicators", [])

        if redirect_hops > 0:
            threat_parts.append(f"{redirect_hops} redirects")

        if suspicious_patterns:
            threat_parts.append(f"{len(suspicious_patterns)} suspicious patterns")

        if threat_indicators:
            threat_parts.append(f"{len(threat_indicators)} threat indicators")

    return " | ".join(threat_parts) if threat_parts else None
```

## Performance Considerations

### Rule Optimization
```yara
rule OptimizedRule
{
    meta:
        description = "Optimized for performance"

    strings:
        $anchor = "specific_identifier" // Use specific anchors
        $pattern = /regex_pattern/ nocase wide ascii

    condition:
        $anchor and $pattern and filesize < 1MB
}
```

### Analysis Limits
- **File Size**: Limit analysis to reasonable content sizes (< 10MB)
- **Timeout**: Set analysis timeout to prevent hanging (30 seconds)
- **Memory**: Monitor memory usage for large content
- **Rule Count**: Optimize rule set for performance vs. coverage

### Scanning Strategy
```python
def optimize_yara_scan(content):
    # Skip binary content unless specifically needed
    if is_binary_content(content):
        return skip_binary_analysis()

    # Limit content size for performance
    if len(content) > MAX_CONTENT_SIZE:
        content = content[:MAX_CONTENT_SIZE]

    # Use targeted rule sets based on content type
    rule_set = select_rules_for_content_type(detect_content_type(content))

    return execute_yara_scan(content, rule_set)
```

## Error Handling

### Common Error Scenarios
```json
{
  "status": "error",
  "error_type": "compilation_error",
  "message": "YARA rule compilation failed",
  "failed_rules": ["malformed_rule.yar"]
}
```

### Error Types
- `compilation_error`: YARA rules failed to compile
- `timeout_error`: Analysis exceeded time limit
- `memory_error`: Insufficient memory for analysis
- `content_error`: Unable to process content format

### Graceful Degradation
```python
def handle_yara_error(error_type, content):
    fallback_result = {
        "status": "error",
        "num_matches": 0,
        "matches": [],
        "redirect_analysis": extract_basic_redirects(content),
        "error_message": get_error_message(error_type)
    }

    return fallback_result
```

## Cross-Provider Validation

### Redirect Chain Correlation
- Compare YARA redirect analysis with Lookyloo behavioral data
- Validate redirect counts across providers
- Cross-check final URLs for consistency

### Content Analysis Correlation
- Compare YARA matches with URLScan.io threat indicators
- Validate suspicious patterns with VirusTotal engine results
- Cross-reference domain analysis with WHOIS age data

### Confidence Scoring
```python
def calculate_yara_confidence(matches, redirect_analysis):
    confidence_factors = []

    # Match-based confidence
    if matches:
        confidence_factors.append(f"{len(matches)} YARA matches")

    # Redirect-based confidence
    redirect_summary = redirect_analysis.get("summary", "")
    if redirect_summary and redirect_summary != "No redirects detected":
        confidence_factors.append(f"Redirects: {redirect_summary}")

    return " | ".join(confidence_factors) if confidence_factors else "No matches"
```

## Rule Management

### Rule Categories
- **Core Rules**: Essential malware and phishing detection
- **Experimental Rules**: New threat patterns under evaluation
- **Custom Rules**: Organization-specific threat patterns
- **Regional Rules**: Geography-specific threat patterns

### Rule Updates
```python
def update_yara_rules():
    # Download latest rule updates
    new_rules = download_rule_updates()

    # Validate rule compilation
    validated_rules = validate_rule_compilation(new_rules)

    # Deploy to scanning engine
    deploy_rules_to_scanner(validated_rules)

    # Update rule metadata
    update_rule_metadata(validated_rules)
```

This YARA analysis framework provides pattern-based threat detection that complements the network intelligence and metadata analysis from other providers, enabling comprehensive URL threat assessment.
