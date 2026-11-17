#!/usr/bin/env python3
"""Lightweight Link Analyzer provider for redirect/DNS analysis (ported functionality).

This provider performs a safe HTTP(S) request to the target URL, follows redirects
(to a limited depth handled by requests), records redirect count, detects domain
changes, collects resolved IPs for the final host, and surfaces simple heuristics
(e.g., URL shorteners) as suspicious signals. It conforms to the new architecture.
"""

import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel


class LinkAnalyzerProvider(BaseProvider):
    """Link Analyzer provider focusing on HTTP redirects and DNS resolution."""

    def __init__(
        self, provider_name: str = "link_analyzer", config: Dict | None = None
    ):
        # No dedicated config class; use base config via enum template if present
        super().__init__(provider_name, config)

    def is_available(self) -> bool:
        """Link analyzer is available for URLs (requires no external API)."""
        return True

    def scan(self, target: str) -> ProviderResult:
        """Analyze link behavior: redirects, domain change, DNS resolution."""
        # Require URL format; if domain only, normalize to https://
        if not target.startswith(("http://", "https://")):
            url = f"https://{target}"
        else:
            url = target

        try:
            # Perform GET with redirects allowed; low risk headers
            resp = requests.get(
                url,
                allow_redirects=True,
                timeout=self.config.timeout,
                headers={"User-Agent": "url-checker-tools/1.0 (link-analyzer)"},
                verify=True,
            )

            history = resp.history or []
            redirect_count = len(history)
            final_url = str(resp.url)

            orig_domain = urlparse(url).netloc.lower()
            final_domain = urlparse(final_url).netloc.lower()

            # Normalize hosts for domain change detection: ignore leading 'www.' differences
            def _norm(host: Optional[str]) -> str:
                h = (host or "").lower()
                return h[4:] if h.startswith("www.") else h

            domain_changed = (
                (_norm(final_domain) != _norm(orig_domain))
                if final_domain and orig_domain
                else False
            )

            # Resolve final domain to IPs (best effort)
            resolved_ips: List[str] = []
            try:
                if final_domain:
                    for family in (socket.AF_INET, socket.AF_INET6):
                        try:
                            infos = socket.getaddrinfo(
                                final_domain, None, family, socket.SOCK_STREAM
                            )
                            for info in infos:
                                ip = info[4][0]
                                if ip and ip not in resolved_ips:
                                    resolved_ips.append(ip)
                        except Exception:
                            continue
            except Exception:
                pass

            # Simple heuristics
            shorteners = {
                "bit.ly",
                "t.co",
                "tinyurl.com",
                "goo.gl",
                "ow.ly",
                "is.gd",
                "buff.ly",
            }
            contains_shorteners = (
                orig_domain in shorteners or final_domain in shorteners
            )

            # Block-page heuristic (very light): HTTP status 4xx/5xx with short body
            is_blocked = (400 <= resp.status_code < 600) and (
                len(resp.text or "") < 2048
            )

            details = {
                "original_url": url,
                "final_url": final_url,
                "redirect_count": redirect_count,
                "domain_changed": domain_changed,
                "status_code": resp.status_code,
                "resolved_ips": resolved_ips,
                "contains_shorteners": contains_shorteners,
                "is_blocked": is_blocked,
            }

            # Decide threat level: domain change with multiple redirects or shorteners => suspicious
            if (
                domain_changed
                or redirect_count >= 3
                or contains_shorteners
                or is_blocked
            ):
                threat_level = ThreatLevel.SUSPICIOUS
                confidence = 0.65
                return self._create_threat_result(
                    target=url,
                    threat_level=threat_level,
                    details=details,
                    confidence=confidence,
                )
            else:
                return self._create_safe_result(
                    target=url, details=details, confidence=0.9
                )

        except Exception as e:
            return self._create_error_result(target, f"link analysis error: {e}")
