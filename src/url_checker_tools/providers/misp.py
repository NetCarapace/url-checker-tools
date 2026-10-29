#!/usr/bin/env python3
"""Clean MISP provider implementation using new architecture - POC"""

from datetime import datetime, timedelta
from typing import Any, Dict, List
from urllib.parse import urlparse

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.celery_app import celery_app
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class MISPProvider(BaseProvider):
    """Clean MISP provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "misp", config: Dict | None = None):
        """Initialize provider with MISP configuration."""
        super().__init__(provider_name, config)  # Let BaseProvider auto-load config
        self._misp_client = None

    def is_available(self) -> bool:
        """Check if MISP is properly configured."""
        try:
            import pymisp  # noqa: F401

            return bool(self.config.url and self.config.key)
        except ImportError:
            return False

    def _initialize_misp_client(self):
        """Initialize PyMISP client if not already done."""
        if self._misp_client is None:
            try:
                from pymisp import PyMISP

                self._misp_client = PyMISP(
                    self.config.url,
                    self.config.key,
                    ssl=self.config.verifycert,
                    debug=False,
                )

                # Test connection
                user_info = self._misp_client.get_user()
                if not user_info or "errors" in user_info:
                    raise Exception("Failed to authenticate with MISP server")

            except ImportError:
                raise Exception("pymisp library not available")
            except Exception as e:
                raise Exception(f"Failed to initialize MISP client: {e}")

    def scan(self, target: str) -> ProviderResult:
        """Scan target with MISP API."""
        # Extract different searchable components from target
        search_terms = self._extract_search_terms(target)

        # Search MISP for each component
        all_events = []
        for term in search_terms:
            events = self._search_misp(term)
            if events:
                all_events.extend(events)

        if not all_events:
            # No matches found in MISP
            return self._create_safe_result(
                target,
                {
                    "events_found": 0,
                    "search_terms": search_terms,
                    "misp_instance": self.config.url,
                },
                confidence=0.7,
            )

        # Analyze found events
        return self._analyze_misp_events(target, all_events, search_terms)

    def _extract_search_terms(self, target: str) -> List[str]:
        """Extract searchable terms from target."""
        terms = [target]  # Always search for the full target

        # If it's a URL, also search for domain and path components
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)

            # Add domain
            if parsed.netloc:
                terms.append(parsed.netloc)

            # Add path if significant
            if parsed.path and len(parsed.path) > 1:
                terms.append(parsed.path)

        return list(set(terms))  # Remove duplicates

    def _search_misp(self, term: str) -> List[Any]:
        """Search MISP for a specific term using PyMISP, returning MISPEvent objects."""
        self._initialize_misp_client()

        try:
            search_results = self._misp_client.search(
                value=term,
                type_attribute=["url", "domain", "hostname"],
                limit=50,
                page=1,
                pythonify=True,
            )

            if isinstance(search_results, list):
                return search_results

            return []

        except Exception as e:
            raise Exception(f"MISP search failed: {e}")

    def _analyze_misp_events(
        self, target: str, events: List[Any], search_terms: List[str]
    ) -> ProviderResult:
        """Analyze MISP events (MISPEvent objects) to determine threat level."""
        if not events:
            return self._create_safe_result(target, {}, confidence=0.7)

        threat_levels = []
        categories = set()
        recent_events = 0
        total_events = len(events)

        recent_threshold = datetime.now() - timedelta(days=30)

        for event in events:
            # Use getattr for MISPEvent objects (pythonify=True)
            try:
                event_date_str = getattr(event, "date", None)
                if event_date_str:
                    event_date = datetime.strptime(str(event_date_str), "%Y-%m-%d")
                    if event_date > recent_threshold:
                        recent_events += 1
            except (ValueError, TypeError):
                pass

            threat_level_id = str(getattr(event, "threat_level_id", "4"))
            categories.add(getattr(event, "info", "Unknown"))

            if threat_level_id in ("1", "2"):
                threat_levels.append("high")
            elif threat_level_id == "3":
                threat_levels.append("medium")
            else:
                threat_levels.append("low")

        if recent_events >= 3 or "high" in threat_levels[:3]:
            threat_level = ThreatLevel.MALICIOUS
            is_threat = True
            confidence = min(0.9, 0.6 + (recent_events * 0.1))
        elif recent_events >= 1 or "medium" in threat_levels:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = min(0.8, 0.5 + (recent_events * 0.1))
        elif total_events >= 5:
            threat_level = ThreatLevel.SUSPICIOUS
            is_threat = True
            confidence = 0.6
        else:
            threat_level = ThreatLevel.SAFE
            is_threat = False
            confidence = 0.7

        details = {
            "events_found": total_events,
            "recent_events": recent_events,
            "search_terms": search_terms,
            "categories": list(categories),
            "threat_levels": list(set(threat_levels)),
            "misp_instance": self.config.url,
            "sample_events": [
                {
                    "info": getattr(e, "info", "Unknown"),
                    "date": str(getattr(e, "date", "Unknown")),
                    "threat_level": str(getattr(e, "threat_level_id", "4")),
                }
                for e in events[:5]
            ],
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


# Create Celery task
@celery_app.task(name="misp_scan")
def misp_scan(target: str, workflow_id: str = None) -> dict:
    """Celery task for MISP scanning."""
    with MISPProvider() as provider:
        if workflow_id:
            provider.set_workflow_id(workflow_id)

        result = provider.scan_with_timing(target)

        # Return serializable result
        return {
            "provider": result.provider,
            "target": result.target,
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "details": result.details,
            "execution_time": result.execution_time,
            "error_message": result.error_message,
            "timestamp": result.timestamp.isoformat(),
        }
