#!/usr/bin/env python3
"""Clean LookyLoo provider implementation using new architecture."""

import time
from typing import Dict

from pylookyloo import Lookyloo

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class LookyLooProvider(BaseProvider):
    """Clean LookyLoo provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "lookyloo", config: Dict | None = None):
        """Initialize provider with LookyLoo configuration."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if LookyLoo is available."""
        return True  # Public service, no API key required

    def scan(self, target: str) -> ProviderResult:
        """Scan target with LookyLoo API using pylookyloo library."""
        # LookyLoo requires full URLs
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        try:
            # Initialize LookyLoo client
            lookyloo = Lookyloo(root_url=self.config.endpoint)

            # Submit URL for capture
            uuid = lookyloo.submit(url=target)
            capture_uuid = self._extract_uuid_from_response(uuid)

            # Wait for capture completion and get results
            return self._wait_and_get_results(lookyloo, target, capture_uuid)

        except Exception as e:
            return self._create_error_result(target, f"LookyLoo scan failed: {str(e)}")

    def _extract_uuid_from_response(self, uuid: str) -> str:
        """Extract actual UUID from LookyLoo response."""
        if uuid.startswith("http"):
            # Extract UUID from URL like https://lookyloo.circl.lu/tree/81c8d4bf-b6e4-42db-be08-ef80156aed8b
            return uuid.split("/")[-1]
        return uuid

    def _wait_and_get_results(
        self, lookyloo: Lookyloo, target: str, capture_uuid: str
    ) -> ProviderResult:
        """Wait for capture completion and retrieve results using proper API."""
        max_attempts = 8  # 8 attempts = up to 40 seconds
        attempt = 0

        while attempt < max_attempts:
            # Wait before checking (first check after 15 seconds, then 5-second intervals)
            wait_time = 15 if attempt == 0 else 5
            time.sleep(wait_time)
            attempt += 1

            # Show progress to user
            print(
                f"  LookyLoo capture in progress... [{attempt}/{max_attempts}]",
                end="\r",
            )

            try:
                # Check capture status using pylookyloo
                status_response = lookyloo.get_status(capture_uuid)
                status_code = (
                    status_response.get("status_code", -1)
                    if isinstance(status_response, dict)
                    else -1
                )

                if status_code == 1:
                    # Capture is complete, verify data is available
                    try:
                        info_data = lookyloo.get_info(capture_uuid)
                        if info_data and not info_data.get("error"):
                            # Clear progress line and return results
                            print(" " * 50, end="\r")
                            return self._parse_lookyloo_response(
                                target, capture_uuid, info_data
                            )
                    except Exception:
                        # Data not ready yet, continue waiting
                        continue

                # If we haven't reached max attempts, continue waiting
                if attempt < max_attempts:
                    continue

            except Exception as e:
                # If there's an error and we haven't reached max attempts, continue
                if attempt < max_attempts:
                    continue
                # Otherwise, clear progress and re-raise
                print(" " * 50, end="\r")
                raise e

        # If we get here, capture took too long
        print(" " * 50, end="\r")
        return self._create_error_result(
            target,
            f"LookyLoo capture {capture_uuid} took too long to complete (timeout after {max_attempts * 5} seconds)",
        )

    def _parse_lookyloo_response(
        self, target: str, capture_uuid: str, response: Dict
    ) -> ProviderResult:
        """Parse LookyLoo API response into standard result."""
        if response.get("error"):
            return self._create_error_result(
                target,
                f"LookyLoo info error: {response.get('error_message', 'Unknown error')}",
            )

        # Analyze capture info
        redirects = response.get("redirects", [])
        final_url = response.get("final_url", target)

        # Check for suspicious indicators
        suspicious_indicators = []

        # Multiple redirects can be suspicious
        if len(redirects) > 3:
            suspicious_indicators.append(f"{len(redirects)} redirects detected")

        # Domain changes
        from urllib.parse import urlparse

        original_domain = urlparse(target).netloc
        final_domain = urlparse(final_url).netloc

        if original_domain != final_domain:
            suspicious_indicators.append(
                f"Domain changed: {original_domain} -> {final_domain}"
            )

        # Determine threat level based on indicators
        if len(suspicious_indicators) >= 2:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = 0.7
        elif len(suspicious_indicators) == 1:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = 0.5
        else:
            threat_level = ThreatLevel.SAFE
            is_threat = False
            confidence = 0.8

        # Build details
        details = {
            "capture_uuid": capture_uuid,
            "final_url": final_url,
            "redirects": redirects,
            "redirect_count": len(redirects),
            "domain_changed": original_domain != final_domain,
            "suspicious_indicators": suspicious_indicators,
            "lookyloo_url": f"{self.config.endpoint}/tree/{capture_uuid}",
            "raw_response": response,
        }

        if is_threat:
            return self._create_threat_result(
                target=target,
                threat_level=threat_level,
                confidence=confidence,
                details=details,
            )
        else:
            return self._create_safe_result(
                target=target,
                details=details,
                confidence=confidence,
            )
