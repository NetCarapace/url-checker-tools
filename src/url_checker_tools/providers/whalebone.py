#!/usr/bin/env python3
"""Clean Whalebone provider implementation using new architecture."""

from typing import Dict
from urllib.parse import urlparse

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class WhaleboneProvider(BaseProvider):
    """Clean Whalebone provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "whalebone", config: Dict | None = None):
        """Initialize Whalebone provider with auto-loaded configuration."""
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Check if Whalebone is properly configured."""
        return bool(self.config.api_key and self.config.user_id)

    def scan(self, target: str) -> ProviderResult:
        """Scan target with Whalebone API."""
        # Extract domain from URL if needed
        domain = self._extract_domain(target)

        # Make API request following old implementation pattern
        # Endpoint already includes base path, we pass domain as query param
        url = self.config.endpoint
        headers = {
            "Wb-Access-Key": self.config.user_id,
            "Wb-Secret-Key": self.config.api_key,
            "Accept": "application/json",
        }
        params = {"fqdn": domain}

        response_data, execution_time = self.http.get(
            url, headers=headers, params=params
        )

        # Handle errors
        if response_data.get("error"):
            return self._create_error_result(
                target, f"Whalebone API error: {response_data['error_message']}"
            )

        # Parse response
        return self._parse_whalebone_response(target, response_data)

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or return as-is if already a domain."""
        if target.startswith(("http://", "https://")):
            return urlparse(target).netloc
        return target

    def _classify_whalebone_category(self, category: str) -> str:
        """Classify Whalebone content category based on configured blacklists."""
        category_lower = category.lower().strip()

        # Get blacklist categories from config
        security_blacklist = [
            cat.lower() for cat in (self.config.security_blacklisted_categories or [])
        ]
        policy_blacklist = [
            cat.lower() for cat in (self.config.policy_blacklisted_categories or [])
        ]

        if category_lower in security_blacklist:
            return "security_threat"
        elif category_lower in policy_blacklist:
            return "policy_block"
        else:
            # Categories not in blacklists are considered unknown
            return "unknown"

    def _parse_whalebone_response(self, target: str, response: Dict) -> ProviderResult:
        """Parse Whalebone API response into standard result.
        Expected response shape (as per wb_test):
        {
            'threats': [{ 'threat_type': 'phishing', 'accuracy': 90, 'first_detection': '...'}, ...],
            'content_categories': []
        }
        """
        threats_all = response.get("threats", []) or []
        content_categories = response.get("content_categories", []) or []

        # Filter out 0% accuracy threats (unreliable) and normalize
        threats = [
            t
            for t in threats_all
            if isinstance(t, dict) and int(t.get("accuracy", 0)) > 0
        ]

        # Normalize and classify categories using config
        normalized_categories = []
        security_cats, policy_cats, safe_cats, unknown_cats = [], [], [], []
        for cat in content_categories:
            if not isinstance(cat, str):
                continue
            c = cat.strip().lower()
            normalized_categories.append(c)

            # Classify category based on configured blacklists
            classification = self._classify_whalebone_category(c)
            if classification == "security_threat":
                security_cats.append(c)
            elif classification == "policy_block":
                policy_cats.append(c)
            elif classification == "safe":
                safe_cats.append(c)
            else:
                unknown_cats.append(c)

        # Extract threat types (deduplicated) and compute max accuracy
        seen = set()
        threat_types = []
        accuracies = []
        for t in threats:
            tt = t.get("threat_type")
            if tt and tt not in seen:
                threat_types.append(tt)
                seen.add(tt)
            accuracies.append(int(t.get("accuracy", 0)))
        max_accuracy = max(accuracies) if accuracies else 0

        # Determine if any threat meets accuracy threshold
        has_significant_threat = any(
            (int(t.get("accuracy", 0)) >= self.config.min_threat_accuracy)
            for t in threats
        )

        # Final decision includes category classification
        if has_significant_threat or security_cats:
            threat_level = (
                ThreatLevel.MALICIOUS
                if max_accuracy >= 80 or security_cats
                else ThreatLevel.SUSPICIOUS
            )
            is_threat = True
        elif threats:
            # Some threats present but below threshold
            threat_level = (
                ThreatLevel.SUSPICIOUS if max_accuracy >= 50 else ThreatLevel.SAFE
            )
            is_threat = max_accuracy >= 50
        elif policy_cats or unknown_cats:
            # Policy-only or unknown categories: suspicious at most
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
        else:
            threat_level = ThreatLevel.SAFE
            is_threat = False

        # Build details aligned with actual API and classification
        details = {
            "threats": threats,  # filtered (no 0% accuracy)
            "threat_types": threat_types,  # de-duplicated
            "max_accuracy": max_accuracy,
            "content_categories": content_categories,
            "categories": normalized_categories,
            "category_classification": {
                "security": list(sorted(set(security_cats))),
                "policy": list(sorted(set(policy_cats))),
                "safe": list(sorted(set(safe_cats))),
                "unknown": list(sorted(set(unknown_cats))),
            },
            "raw_response": response,
        }

        # Confidence based on max accuracy and categories
        base_conf = max_accuracy / 100.0 if max_accuracy else 0.0
        if security_cats:
            base_conf = max(base_conf, 0.85)
        elif policy_cats or unknown_cats:
            base_conf = max(base_conf, 0.65)

        if is_threat:
            return self._create_threat_result(
                target=target,
                threat_level=threat_level,
                details=details,
                confidence=min(0.95, max(0.6, base_conf)),
            )
        else:
            return self._create_safe_result(
                target=target,
                details=details,
                confidence=max(0.85, (100 - max_accuracy) / 100.0),
            )
