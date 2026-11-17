#!/usr/bin/env python3
"""Clean Google Safe Browsing provider implementation using new architecture."""

from typing import Dict

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class GoogleSafeBrowsingProvider(BaseProvider):
    """Clean Google Safe Browsing provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "google_sb", config: Dict | None = None):
        """Initialize provider with Google Safe Browsing configuration."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if Google Safe Browsing is properly configured."""
        return bool(self.config.api_key)

    def scan(self, target: str) -> ProviderResult:
        """Scan target with Google Safe Browsing API."""
        # Prepare request payload
        payload = {
            "client": {
                "clientId": self.config.client_id,
                "clientVersion": self.config.client_version,
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target}],
            },
        }

        # Make API request
        headers = {"Content-Type": "application/json"}

        # Add API key as query parameter
        url = f"{self.config.endpoint}?key={self.config.api_key}"

        response_data, execution_time = self.http.post(
            url, headers=headers, json_data=payload
        )

        # Handle errors
        if response_data.get("error"):
            return self._create_error_result(
                target,
                f"Google Safe Browsing API error: {response_data.get('error_message', 'Unknown error')}",
            )

        # Parse response
        return self._parse_google_sb_response(target, response_data)

    def _parse_google_sb_response(self, target: str, response: Dict) -> ProviderResult:
        """Parse Google Safe Browsing API response into standard result."""
        matches = response.get("matches", [])

        if not matches:
            # No threats detected
            return self._create_safe_result(
                target, {"matches": [], "safe_browsing_status": "clean"}, confidence=0.9
            )

        # Threats detected - analyze severity
        threat_types = [match.get("threatType", "") for match in matches]
        platforms = [match.get("platformType", "") for match in matches]

        # Determine threat level based on threat types
        critical_threats = ["MALWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
        malicious_threats = ["SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

        if any(threat in critical_threats for threat in threat_types):
            threat_level = ThreatLevel.CRITICAL
            confidence = 0.95
        elif any(threat in malicious_threats for threat in threat_types):
            threat_level = ThreatLevel.MALICIOUS
            confidence = 0.9
        else:
            threat_level = ThreatLevel.SUSPICIOUS
            confidence = 0.8

        # Build details
        details = {
            "matches": matches,
            "threat_types": threat_types,
            "platforms": platforms,
            "match_count": len(matches),
            "raw_response": response,
        }

        return self._create_threat_result(
            target=target,
            threat_level=threat_level,
            details=details,
            confidence=confidence,
        )
