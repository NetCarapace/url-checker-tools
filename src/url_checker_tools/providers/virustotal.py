#!/usr/bin/env python3
"""Clean VirusTotal provider implementation using new architecture."""

import base64
import re
from typing import Dict

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class VirusTotalProvider(BaseProvider):
    """Clean VirusTotal provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "virustotal", config: Dict | None = None):
        """Initialize VirusTotal provider."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if VirusTotal is properly configured."""
        return bool(self.config.api_key)

    def scan(self, target: str) -> ProviderResult:
        """Scan target with VirusTotal API."""
        # Encode URL for VirusTotal API
        url_id = base64.urlsafe_b64encode(target.encode()).decode().rstrip("=")

        # Make API request
        url = f"{self.config.endpoint}/urls/{url_id}"
        headers = {
            "X-Apikey": self.config.api_key,
        }

        response_data, execution_time = self.http.get(url, headers=headers)

        # Handle errors
        if response_data.get("error"):
            return self._create_error_result(
                target,
                f"VirusTotal API error: {response_data.get('error_message', 'Unknown error')}",
            )

        # Parse response
        return self._parse_virustotal_response(target, response_data)

    def _parse_virustotal_response(self, target: str, response: Dict) -> ProviderResult:
        """Parse VirusTotal API response into standard result."""
        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        # Count detections
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        total_engines = malicious + suspicious + harmless + undetected

        # Determine threat level
        if total_engines == 0:
            threat_level = ThreatLevel.UNKNOWN
            is_threat = False
            confidence = 0.0
        elif malicious >= 2:  # Multiple engines detected malicious
            threat_level = ThreatLevel.MALICIOUS
            is_threat = True
            confidence = min(0.9, malicious / max(total_engines, 1))
        elif malicious >= 1 or suspicious >= 2:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = min(0.7, (malicious + suspicious) / max(total_engines, 1))
        else:
            threat_level = ThreatLevel.SAFE
            is_threat = False
            confidence = max(0.8, harmless / max(total_engines, 1))

        # Extract VT categories/keywords from attributes and analysis results
        vt_cats_raw = []
        # attributes.categories may be a dict of vendor->category or a list
        cats_attr = attributes.get("categories")
        if isinstance(cats_attr, dict):
            vt_cats_raw.extend(
                [str(v) for v in cats_attr.values() if isinstance(v, str)]
            )
        elif isinstance(cats_attr, list):
            vt_cats_raw.extend([str(v) for v in cats_attr if isinstance(v, str)])
        # attributes.tags may contain useful keywords
        tags_attr = attributes.get("tags") or []
        if isinstance(tags_attr, list):
            vt_cats_raw.extend([str(v) for v in tags_attr if isinstance(v, str)])
        # Derive keywords from last_analysis_results 'result' fields (e.g., 'phishing site')
        lar = attributes.get("last_analysis_results") or {}
        if isinstance(lar, dict):
            for engine, res in lar.items():
                if not isinstance(res, dict):
                    continue
                result_text = res.get("result")
                if isinstance(result_text, str) and result_text:
                    vt_cats_raw.append(result_text)
        # Normalize, deduplicate, and filter generic labels
        seen = set()
        generic = {
            "clean",
            "harmless",
            "undetected",
            "unrated",
            "malicious",
            "suspicious",
            "clean site",
        }
        vt_categories = []
        for item in vt_cats_raw:
            norm = item.strip().lower()
            # Remove label source suffixes like "(alphamountain.ai)" or "- alphamountain.ai"
            norm = re.sub(r"\s*\(alphamountain\.ai\)\s*", " ", norm)
            norm = re.sub(r"\s*-\s*alphamountain\.ai\s*", " ", norm)
            # If the remaining token is just the label source, drop it
            if norm.strip() == "alphamountain.ai":
                continue
            # Collapse multiple spaces and trim
            norm = re.sub(r"\s{2,}", " ", norm).strip()
            if not norm or norm in generic:
                continue
            if norm not in seen:
                vt_categories.append(norm)
                seen.add(norm)

        # Build details
        details = {
            "stats": stats,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total_engines,
            "scan_date": attributes.get("last_analysis_date"),
            "categories_vt": vt_categories,
            # Alias to a generic 'categories' key for downstream summaries
            "categories": vt_categories,
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
