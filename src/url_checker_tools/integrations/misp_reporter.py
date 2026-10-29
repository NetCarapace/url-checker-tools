#!/usr/bin/env python3
"""MISP reporter implementation for threat intelligence integration - POC."""

import logging
import warnings
from typing import Any, Dict, List, Optional

from url_checker_tools.config.provider_config import ProviderConfigTemplate
from url_checker_tools.core.results import ProviderResult
from url_checker_tools.core.utils import ConfigDict


class MISPReporter:
    """MISP reporter for submitting threat intelligence."""

    def __init__(self, verbose: bool = False):
        """Initialize MISP reporter with configuration.
        Use the global auto-populated provider configs so credentials are loaded
        from keyring/env and aliases are normalized.
        """
        try:
            all_configs = ProviderConfigTemplate.get_all_provider_configs()
            raw_config = all_configs.get(
                "misp", ProviderConfigTemplate.get_misp_config()
            )
        except Exception:
            raw_config = ProviderConfigTemplate.get_misp_config()
        self.config = ConfigDict(raw_config)
        self._logger = logging.getLogger(__name__)
        self._misp_client = None
        self._verbose = verbose

        if not verbose:
            warnings.filterwarnings(
                "ignore", message="Unverified HTTPS request is being made"
            )
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def is_available(self) -> bool:
        """Check if MISP reporter is properly configured."""

        have_key = bool(
            getattr(self.config, "api_key", None) or getattr(self.config, "key", None)
        )
        have_url = bool(getattr(self.config, "url", None))
        return bool(have_url and have_key)

    def _initialize_misp_client(self):
        """Initialize PyMISP client if not already done."""
        if self._misp_client is None:
            try:
                from pymisp import PyMISP

                api_key = getattr(self.config, "api_key", None) or getattr(
                    self.config, "key", None
                )
                verify = getattr(self.config, "verify_ssl", None)
                if verify is None:
                    verify = getattr(self.config, "verifycert", False)

                self._misp_client = PyMISP(
                    self.config.url,
                    api_key,
                    ssl=verify,
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

    def create_event(
        self, target: str, results: List[ProviderResult], session_id: str
    ) -> Optional[Dict[str, Any]]:
        """Create MISP event from scan results."""
        # Filter for threat results first
        threat_results = [r for r in results if r.is_threat]
        if not threat_results:
            return None

        # Only initialize MISP client if we have threats to report
        self._initialize_misp_client()

        try:

            # Create event info
            threat_count = len(threat_results)
            provider_names = [r.provider for r in threat_results]

            event_info = f"Threat Analysis: {target} [CRITICAL] - SID: {session_id}"

            # Create MISP event
            event = {
                "info": event_info,
                "threat_level_id": "1",  # High
                "analysis": "1",  # Ongoing
                "distribution": "0",  # Your organization only
                "published": False,
            }

            misp_event = self._misp_client.add_event(event, pythonify=True)
            if not misp_event or hasattr(misp_event, "errors"):
                raise Exception("Failed to create MISP event")

            event_id = misp_event.id
            event_uuid = getattr(misp_event, "uuid", None)

            threat_intel_summary = []
            provider_tags = []
            whalebone_categories = []
            whalebone_classification = None
            link_analyzer_details = None
            link_analyzer_verdict = None

            for result in results:
                # Normalize provider name and details
                provider_name = (
                    result.provider.lower() if hasattr(result, "provider") else ""
                )
                details = (
                    result.details
                    if isinstance(getattr(result, "details", None), dict)
                    else {}
                )

                if provider_name == "link_analyzer":
                    try:
                        tl = getattr(result, "threat_level", None)
                        tl_val = getattr(tl, "value", "unknown") if tl else "unknown"
                        link_analyzer_verdict = (
                            tl_val.capitalize()
                            if isinstance(tl_val, str)
                            else "Unknown"
                        )
                    except Exception:
                        link_analyzer_verdict = "Unknown"
                    link_analyzer_details = details
                    continue

                try:
                    tl = getattr(result, "threat_level", None)
                    tl_val = getattr(tl, "value", None)
                    verdict_map = {
                        "malicious": "Malicious",
                        "critical": "Critical",
                        "suspicious": "Suspicious",
                        "safe": "Safe",
                        "unknown": "Unknown",
                        "error": "Error",
                    }
                    base_verdict = verdict_map.get(tl_val, "Unknown")
                except Exception:
                    base_verdict = "Unknown"
                threat_intel_summary.append(
                    f"{result.provider.upper()}: {base_verdict}"
                )

                # Add provider-specific details
                if provider_name == "virustotal" and details:
                    malicious_count = details.get("malicious_count", 0)
                    total_count = details.get("total_engines", 0)
                    if malicious_count > 0 and total_count > 0:
                        vt_segment = f"VT: Malicious ({malicious_count}/{total_count})"
                    elif total_count > 0:
                        vt_segment = (
                            f"VT: Clean ({total_count - malicious_count} clean engines)"
                        )
                    else:
                        vt_segment = "VT: Unknown"
                    # Append VT categories/tags if available
                    cats = (
                        details.get("categories") or details.get("categories_vt") or []
                    )
                    if isinstance(cats, list) and cats:
                        seen_c = set()
                        unique_cats = []
                        for c in cats:
                            if isinstance(c, str):
                                cn = c.strip().lower()
                                if cn and cn not in seen_c:
                                    seen_c.add(cn)
                                    unique_cats.append(cn)
                        if unique_cats:
                            vt_segment = (
                                f"{vt_segment} [Categories: {', '.join(unique_cats)}]"
                            )
                    threat_intel_summary[-1] = vt_segment

                elif provider_name == "whalebone" and details:
                    categories = details.get("categories", []) or []
                    # Prefer max_accuracy from provider details
                    max_accuracy = (
                        details.get("max_accuracy", details.get("accuracy", 0)) or 0
                    )
                    # Extract threat types (deduplicated)
                    threat_types = details.get("threat_types", []) or []
                    threat_types = [t for t in threat_types if isinstance(t, str) and t]
                    threat_types_str = (
                        ", ".join(sorted(set(threat_types))) if threat_types else ""
                    )
                    if categories:
                        whalebone_categories.extend(
                            [c for c in categories if isinstance(c, str)]
                        )
                    if not whalebone_classification:
                        cc = details.get("category_classification", {})
                        if isinstance(cc, dict):
                            whalebone_classification = cc
                    # Build verdict text from result's threat level
                    verdict_text = getattr(
                        getattr(result, "threat_level", None), "value", None
                    )
                    verdict_text = (
                        verdict_text.capitalize()
                        if isinstance(verdict_text, str)
                        else "Unknown"
                    )
                    # Compose base summary including threat types if available
                    if threat_types_str:
                        base = f"WHALEBONE: {verdict_text} ({threat_types_str}; Max accuracy: {int(max_accuracy)}%)"
                    else:
                        base = f"WHALEBONE: {verdict_text} (Max accuracy: {int(max_accuracy)}%)"
                    # Include categories in summary if present
                    if categories:
                        cats_str = ", ".join(
                            sorted(set([c for c in categories if isinstance(c, str)]))
                        )
                        threat_intel_summary[-1] = f"{base} [Categories: {cats_str}]"
                    else:
                        threat_intel_summary[-1] = base

                elif provider_name == "google_sb" and result.is_threat:
                    sb_types = details.get("threat_types", [])
                    if sb_types:
                        threat_intel_summary[-1] = (
                            f"GOOGLE_SB: Malicious ({', '.join(sb_types)})"
                        )

                elif provider_name == "abuseipdb" and details:
                    abuse_confidence = details.get(
                        "abuse_confidence", details.get("abuseConfidencePercentage", 0)
                    )
                    if abuse_confidence > 0:
                        threat_intel_summary[-1] = (
                            f"ABUSEIPDB: {details.get('verdict', 'Suspicious')} (Confidence: {abuse_confidence}%)"
                        )

                # Add provider tags
                provider_tags.append(f"provider:{provider_name}")
                if provider_name == "virustotal":
                    provider_tags.append("provider:virustotal:engines")
                elif provider_name == "whalebone":
                    provider_tags.append("provider:whalebone:categorization")
                elif provider_name == "google_sb":
                    provider_tags.append("provider:google:safe-browsing")
                elif provider_name == "abuseipdb":
                    provider_tags.append("provider:abuseipdb:reputation")

            # Add provider tags to the main comment
            comment_attrs = self._misp_client.search(
                controller="attributes", eventid=event_id, type_attribute="comment"
            )
            if comment_attrs:
                # Normalize to a list
                attrs_list = (
                    comment_attrs
                    if isinstance(comment_attrs, list)
                    else [comment_attrs]
                )
                # Tag the main threat intel comment
                main_comment = None
                for attr in attrs_list:
                    # Support both dict format and pythonify objects
                    if isinstance(attr, dict):
                        attr_value = attr.get("Attribute", attr)
                        # If 'Attribute' is a list, iterate over it
                        if isinstance(attr_value, list):
                            for item in attr_value:
                                if isinstance(item, dict):
                                    value = item.get("value", "")
                                    if (
                                        isinstance(value, str)
                                        and "Threat Intel:" in value
                                    ):
                                        main_comment = item
                                        break
                            if main_comment:
                                break
                        else:
                            attr_dict = attr_value
                            value = (
                                attr_dict.get("value", "")
                                if isinstance(attr_dict, dict)
                                else ""
                            )
                            if (
                                isinstance(value, str)
                                and "Threat Intel:" in value
                                and isinstance(attr_dict, dict)
                            ):
                                main_comment = attr_dict
                                break
                    else:
                        # Unknown type (e.g., string) – skip safely
                        continue

                if (
                    main_comment
                    and isinstance(main_comment, dict)
                    and "uuid" in main_comment
                ):
                    for tag in provider_tags:
                        try:
                            self._misp_client.tag(main_comment["uuid"], tag)
                        except Exception:
                            pass  # Continue if tagging fails

            # Add comprehensive DNS/IP information if available
            dns_ips = []
            network_details = []
            shodan_ips = []

            for result in results:
                # Normalize details to dict per result to avoid attribute errors
                det = (
                    result.details
                    if isinstance(getattr(result, "details", None), dict)
                    else {}
                )
                # Check for DNS resolution data
                if result.provider.lower() in ["link_analyzer", "dns"] and det:
                    resolved_ips = det.get("resolved_ips", [])
                    if resolved_ips:
                        dns_ips.extend(resolved_ips)
                        network_details.append(f"DNS resolved {len(resolved_ips)} IPs")

                # Check for Shodan/InternetDB enrichment
                if result.provider.lower() == "shodan" and det:
                    enriched_ips = det.get("enriched_ips", [])
                    if enriched_ips:
                        shodan_ips.extend(enriched_ips)
                        network_details.append(
                            f"Shodan enriched {len(enriched_ips)} IPs"
                        )

                # Check for AbuseIPDB IP analysis
                if result.provider.lower() == "abuseipdb" and det:
                    analyzed_ips = det.get("analyzed_ips", [])
                    if analyzed_ips:
                        network_details.append(
                            f"AbuseIPDB analyzed {len(analyzed_ips)} IPs"
                        )

            # Add comprehensive threat scoring and metadata using unified scorer
            from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer

            scorer = UnifiedThreatScorer()
            scoring_data = scorer.calculate_threat_score(results)

            total_providers = len(results)
            clean_providers = len([r for r in results if not r.is_threat])
            threat_score = scoring_data["final_score"]

            # Add comprehensive threat intelligence tags
            self._misp_client.tag(misp_event, "urlchecker:verdict=critical")
            self._misp_client.tag(misp_event, f"urlchecker:score={threat_score}")
            self._misp_client.tag(misp_event, f"urlchecker:providers={total_providers}")
            self._misp_client.tag(misp_event, f"urlchecker:threats={threat_count}")
            self._misp_client.tag(misp_event, "tlp:white")

            # Add provider-specific verdict tags
            for result in results:
                if result.is_threat:
                    self._misp_client.tag(
                        misp_event, f"verdict:malicious:{result.provider.lower()}"
                    )
                else:
                    self._misp_client.tag(
                        misp_event, f"verdict:clean:{result.provider.lower()}"
                    )

            # Add analysis confidence tags
            if threat_count == 1:
                self._misp_client.tag(misp_event, "confidence:single-source")
            elif threat_count >= 2:
                self._misp_client.tag(misp_event, "confidence:multi-source")

            if total_providers >= 5:
                self._misp_client.tag(misp_event, "coverage:comprehensive")

            try:
                # 1) URL ATTRIBUTE (added first, should appear at top)
                self._misp_client.add_attribute(
                    event_id,
                    {
                        "type": "url",
                        "value": target,
                        "category": "Network activity",
                        "to_ids": True,
                        "comment": f"Primary target URL (Score: {threat_score}/100)",
                    },
                )

                # 2) DOMAIN ATTRIBUTE (if URL)
                if target.startswith(("http://", "https://")):
                    from urllib.parse import urlparse

                    parsed = urlparse(target)
                    if parsed.netloc:
                        self._misp_client.add_attribute(
                            event_id,
                            {
                                "type": "domain",
                                "value": parsed.netloc,
                                "category": "Network activity",
                                "to_ids": True,
                                "comment": "Domain extracted from target URL",
                            },
                        )

                # 3) WHOIS DETAILS (if available)
                whois_result = next(
                    (
                        r
                        for r in results
                        if getattr(r, "provider", "").lower() == "whois"
                    ),
                    None,
                )
                if whois_result:
                    wdet = (
                        whois_result.details
                        if isinstance(getattr(whois_result, "details", None), dict)
                        else {}
                    )
                    age_days = wdet.get("domain_age_days", 0)
                    creation_str = wdet.get("creation_date", "Unknown")
                    registrar = wdet.get("registrar", "Unknown")

                    whois_lines = [
                        "WHOIS:",
                        f"- Domain age: {age_days or 0} days",
                        f"- Registrar: {registrar}",
                        f"- Created: {creation_str}",
                    ]
                    whois_text = "\n".join(whois_lines)

                    self._misp_client.add_attribute(
                        event_id,
                        {
                            "type": "text",
                            "value": whois_text,
                            "category": "Other",
                            "comment": "WHOIS registration details",
                            "to_ids": False,
                        },
                    )

                # 4) NETWORK ANALYSIS (if available)
                if network_details or dns_ips:
                    lines = ["Network Analysis:"]
                    if network_details:
                        lines.append(f"- Summary: {' | '.join(network_details)}")
                    if shodan_ips:
                        lines.append("- InternetDB/Shodan enrichment available")
                    if dns_ips:
                        seen = set()
                        ordered_ips = []
                        for ip in dns_ips:
                            if ip not in seen:
                                ordered_ips.append(ip)
                                seen.add(ip)
                        lines.append(f"- Resolved IPs ({len(ordered_ips)}):")
                        for ip in ordered_ips[:10]:  # Show first 10 IPs
                            lines.append(f"  - {ip}")
                        if len(ordered_ips) > 10:
                            lines.append(f"  - (+{len(ordered_ips) - 10} more)")
                    network_text = "\n".join(lines)

                    self._misp_client.add_attribute(
                        event_id,
                        {
                            "type": "text",
                            "value": network_text,
                            "category": "Network activity",
                            "comment": "Comprehensive network analysis and DNS/IP resolution",
                            "to_ids": False,
                        },
                    )

                # 5) LINK ANALYSIS (if available)
                if link_analyzer_details:
                    ips = link_analyzer_details.get("resolved_ips", []) or []
                    seen_ips = set()
                    uniq_ips = []
                    for ip in ips:
                        if ip not in seen_ips:
                            uniq_ips.append(ip)
                            seen_ips.add(ip)
                    ip_str = ", ".join(uniq_ips[:10]) + (
                        f" (+{len(uniq_ips)-10} more)" if len(uniq_ips) > 10 else ""
                    )

                    la_lines = [
                        "Link Analysis:",
                        f"- Verdict: {link_analyzer_verdict or 'Unknown'}",
                        f"- Original URL: {link_analyzer_details.get('original_url', '')}",
                        f"- Final URL: {link_analyzer_details.get('final_url', '')}",
                        f"- Redirects: {link_analyzer_details.get('redirect_count', 0)}",
                        f"- Domain Change: {'yes' if link_analyzer_details.get('domain_changed') else 'no'}",
                        f"- Status Code: {link_analyzer_details.get('status_code', 'n/a')}",
                        f"- Resolved IPs: {ip_str if ip_str else 'none'}",
                        f"- Shortener: {'yes' if link_analyzer_details.get('contains_shorteners') else 'no'}",
                        f"- Blocked Page: {'yes' if link_analyzer_details.get('is_blocked') else 'no'}",
                    ]
                    la_text = "\n".join(la_lines)

                    self._misp_client.add_attribute(
                        event_id,
                        {
                            "type": "text",
                            "value": la_text,
                            "category": "Network activity",
                            "comment": "HTTP redirect/destination and DNS resolution analysis",
                            "to_ids": False,
                        },
                    )

                # 6) THREAT INTEL (consolidated)
                if threat_intel_summary:
                    ti_lines = []
                    for seg in threat_intel_summary:
                        if isinstance(seg, str) and seg:
                            ti_lines.append(f"- {seg}")
                    ti_text = "Threat Intel:\n" + (
                        "\n".join(ti_lines) if ti_lines else "None"
                    )
                    self._misp_client.add_attribute(
                        event_id,
                        {
                            "type": "text",
                            "value": ti_text,
                            "category": "Other",
                            "comment": "Consolidated threat intelligence vendor verdicts",
                            "to_ids": False,
                        },
                    )

                # 7) YARA ANALYSIS (if available)
                yara_results = [r for r in results if r.provider.lower() == "yara"]
                if yara_results:
                    yara_result = yara_results[0]
                    yr_details = (
                        yara_result.details
                        if isinstance(getattr(yara_result, "details", None), dict)
                        else {}
                    )
                    yara_details = yr_details.get("scan_summary", "No pattern matches")
                    patterns = (
                        yr_details.get("patterns_matched", []) if yr_details else []
                    )

                    yara_lines = ["YARA Analysis:", f"- Summary: {yara_details}"]
                    if patterns:
                        yara_lines.append("- Patterns matched:")
                        for p in patterns[:5]:  # Limit to first 5 patterns
                            if isinstance(p, str) and p:
                                yara_lines.append(f"  - {p}")
                    yara_text = "\n".join(yara_lines)

                    self._misp_client.add_attribute(
                        event_id,
                        {
                            "type": "text",
                            "value": yara_text,
                            "category": "Payload delivery",
                            "comment": "YARA behavioral analysis and pattern detection",
                            "to_ids": False,
                        },
                    )

                # 8) THREAT ASSESSMENT (added last, should appear at bottom)
                threat_summary = (
                    f"Threat Assessment: {threat_count}/{total_providers} providers flagged as malicious"
                    f" | Clean: {clean_providers}/{total_providers}"
                    f" | Threat Score: {threat_score}/100"
                )
                self._misp_client.add_attribute(
                    event_id,
                    {
                        "type": "comment",
                        "value": threat_summary,
                        "category": "Other",
                        "comment": "Comprehensive threat assessment summary across all providers",
                        "to_ids": False,
                    },
                )

            except Exception as e:
                self._logger.error(f"Failed to add ordered attributes: {e}")

            self._logger.info(
                f"Created comprehensive MISP event {event_id} (UUID: {event_uuid}) with {len(results)} provider results"
            )
            return {"event_id": event_id, "uuid": event_uuid}

        except Exception as e:
            self._logger.error(f"Failed to create MISP event: {e}")
            return None
