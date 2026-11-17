#!/usr/bin/env python3
"""Clean AbuseIPDB provider implementation using new architecture."""

import socket
from typing import Dict
from urllib.parse import urlparse

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class AbuseIPDBProvider(BaseProvider):
    """Clean AbuseIPDB provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "abuseipdb", config: Dict | None = None):
        """Initialize provider with auto-loaded configuration."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if AbuseIPDB is properly configured."""
        return bool(self.config.api_key)

    def scan(self, target: str) -> ProviderResult:
        """Scan target with AbuseIPDB API."""
        # Extract IP from target
        ip = self._extract_ip(target)
        if not ip:
            return self._create_error_result(
                target, "Could not extract IP address from target"
            )

        # Make API request
        url = f"{self.config.endpoint}/check"
        headers = {"Key": self.config.api_key, "Accept": "application/json"}

        params = {
            "ipAddress": ip,
            "maxAgeInDays": str(self.config.max_age_days),
            "verbose": "",
        }

        response_data, execution_time = self.http.get(
            url, headers=headers, params=params
        )

        # Handle errors
        if response_data.get("error"):
            return self._create_error_result(
                target,
                f"AbuseIPDB API error: {response_data.get('error_message', 'Unknown error')}",
            )

        # Parse response
        return self._parse_abuseipdb_response(target, ip, response_data)

    def _extract_ip(self, target: str) -> str:
        """Extract IP address from target (URL or domain)."""
        try:
            # If it's a URL, extract hostname
            if target.startswith(("http://", "https://")):
                hostname = urlparse(target).netloc
            else:
                hostname = target

            # If it's already an IP, return it
            try:
                socket.inet_aton(hostname)
                return hostname
            except socket.error:
                pass

            # Resolve hostname to IP
            ip = socket.gethostbyname(hostname)
            return ip

        except Exception:
            return None

    def _parse_abuseipdb_response(
        self, target: str, ip: str, response: Dict
    ) -> ProviderResult:
        """Parse AbuseIPDB API response into standard result."""
        data = response.get("data", {})

        abuse_confidence = data.get("abuseConfidenceScore", 0)
        is_public = data.get("isPublic", True)
        usage_type = data.get("usageType", "unknown")
        country_code = data.get("countryCode", "unknown")
        reports = data.get("reports", [])

        # Determine threat level based on abuse confidence
        if abuse_confidence >= 75:
            threat_level = ThreatLevel.CRITICAL
            is_threat = True
        elif abuse_confidence >= 50:
            threat_level = ThreatLevel.MALICIOUS
            is_threat = True
        elif abuse_confidence >= 25:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
        elif abuse_confidence >= self.config.confidence_threshold:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
        else:
            threat_level = ThreatLevel.SAFE
            is_threat = False

        # Build details
        details = {
            "ip_address": ip,
            "abuse_confidence": abuse_confidence,
            "is_public": is_public,
            "usage_type": usage_type,
            "country_code": country_code,
            "report_count": len(reports),
            "recent_reports": reports[:5],  # Include up to 5 recent reports
            "raw_response": response,
        }

        # Calculate confidence score
        confidence = min(0.95, max(0.6, abuse_confidence / 100.0))
        if not is_threat:
            confidence = max(0.8, (100 - abuse_confidence) / 100.0)

        if is_threat:
            return self._create_threat_result(
                target=target,
                threat_level=threat_level,
                details=details,
                confidence=confidence,
            )
        else:
            return self._create_safe_result(
                target=target,
                details=details,
                confidence=confidence,
            )
