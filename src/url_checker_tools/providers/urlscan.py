#!/usr/bin/env python3
"""Clean URLScan.io provider implementation using new architecture."""

import time
from typing import Dict

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class URLScanProvider(BaseProvider):
    """Clean URLScan.io provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "urlscan", config: Dict | None = None):
        """Initialize provider with URLScan.io configuration."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if URLScan.io is properly configured."""
        return bool(self.config.api_key)

    def scan(self, target: str) -> ProviderResult:
        """Scan target with URLScan.io API."""
        # URLScan.io requires full URLs
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Submit scan
        submission_result = self._submit_scan(target)
        if submission_result.get("error"):
            return self._create_error_result(
                target,
                f"URLScan submission error: {submission_result['error_message']}",
            )

        # Get scan UUID
        scan_uuid = submission_result.get("uuid")
        if not scan_uuid:
            return self._create_error_result(
                target, "No scan UUID returned from URLScan.io"
            )

        # Wait for scan to complete and get results
        return self._wait_and_get_results(target, scan_uuid)

    def _submit_scan(self, target: str) -> Dict:
        """Submit URL for scanning."""
        url = f"{self.config.endpoint}/scan/"
        headers = {"api-key": self.config.api_key, "Content-Type": "application/json"}

        payload = {"url": target, "visibility": "public", "tags": ["url-checker-tools"]}

        response_data, _ = self.http.post(url, headers=headers, json_data=payload)

        return response_data

    def _wait_and_get_results(self, target: str, scan_uuid: str) -> ProviderResult:
        """Wait for scan completion and retrieve results."""
        max_wait_seconds = 60  # Maximum wait time
        poll_interval = 5  # Poll every 5 seconds
        elapsed = 0

        # URLScan.io recommendation: wait at least 10 seconds before polling
        time.sleep(10)
        elapsed += 10

        while elapsed < max_wait_seconds:
            # Show progress to user
            print(
                f"  URLScan analysis in progress... ({elapsed}s/{max_wait_seconds}s)",
                end="\r",
            )

            try:
                # Get results
                url = f"{self.config.endpoint}/result/{scan_uuid}/"
                headers = {"api-key": self.config.api_key, "Content-Type": "application/json"}
                response_data, _ = self.http.get(url, headers=headers)

                # URLScan.io returns the full result when ready - check for "task" field
                if response_data and "task" in response_data:
                    # Clear progress line and return results
                    print(" " * 50, end="\r")
                    return self._parse_urlscan_response(target, response_data)

            except Exception as e:
                error_str = str(e)
                # Check if it's a 404 (scan still processing) or other error
                if "404" in error_str or "not found" in error_str.lower():
                    # This is expected during polling - just continue without logging
                    pass
                else:
                    # It's a real error, not just processing - clear progress and re-raise
                    print(" " * 50, end="\r")
                    raise e

            # Wait and update elapsed time
            time.sleep(poll_interval)
            elapsed += poll_interval

        # If we get here, scan took too long
        print(" " * 50, end="\r")
        return self._create_error_result(
            target,
            f"URLScan scan {scan_uuid} did not complete within {max_wait_seconds} seconds",
        )

    def _parse_urlscan_response(self, target: str, response: Dict) -> ProviderResult:
        """Parse URLScan.io API response into standard result."""
        data = response.get("data", {})

        # Get verdicts
        verdicts = data.get("verdicts", {})
        overall = verdicts.get("overall", {})

        malicious = overall.get("malicious", False)
        suspicious = overall.get("suspicious", False)
        score = overall.get("score", 0)

        # Get additional info
        page = response.get("page", {})
        lists = response.get("lists", {})

        # Determine threat level
        if malicious:
            threat_level = ThreatLevel.MALICIOUS
            is_threat = True
            confidence = 0.9
        elif suspicious:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = 0.7
        elif score > 50:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = score / 100.0
        else:
            threat_level = ThreatLevel.SAFE
            is_threat = False
            confidence = max(0.8, (100 - score) / 100.0)

        # Build details
        details = {
            "scan_uuid": response.get("task", {}).get("uuid"),
            "score": score,
            "malicious": malicious,
            "suspicious": suspicious,
            "verdicts": verdicts,
            "page_info": {
                "url": page.get("url"),
                "domain": page.get("domain"),
                "country": page.get("country"),
                "server": page.get("server"),
                "ip": page.get("ip"),
            },
            "threat_lists": lists,
            "scan_url": f"https://urlscan.io/result/{response.get('task', {}).get('uuid')}",
            "raw_response": response,
        }

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
