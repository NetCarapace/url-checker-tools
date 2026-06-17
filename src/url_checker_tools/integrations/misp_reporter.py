#!/usr/bin/env python3
"""MISP reporter — creates structured MISP events using pymisp objects."""

import logging
import warnings
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pymisp import MISPEvent, MISPObject, PyMISP

from url_checker_tools.config.provider_config import ProviderConfigTemplate
from url_checker_tools.core.results import ProviderResult
from url_checker_tools.core.utils import ConfigDict


class MISPReporter:
    """Creates structured MISP events from URL scan results using MISPObject instances."""

    def __init__(self, verbose: bool = False):
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
        have_key = bool(
            getattr(self.config, "api_key", None) or getattr(self.config, "key", None)
        )
        have_url = bool(getattr(self.config, "url", None))
        return bool(have_url and have_key)

    def _initialize_misp_client(self):
        if self._misp_client is None:
            try:

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

                user_info = self._misp_client.get_user()
                if not user_info or "errors" in user_info:
                    raise Exception("Failed to authenticate with MISP server")

            except ImportError:
                raise Exception("pymisp library not available")
            except Exception as e:
                raise Exception(f"Failed to initialize MISP client: {e}")

    # -------------------------------------------------------------------------
    # Object builders
    # -------------------------------------------------------------------------

    def _build_url_object(self, target: str, threat_score: int):
        """Object 1 — primary scan target (url object)."""

        obj = MISPObject("url")
        obj.comment = f"Primary scan target (threat score: {threat_score}/100)"
        obj.add_attribute("url", value=target, to_ids=True)

        parsed = urlparse(target)
        if parsed.netloc:
            obj.add_attribute("domain", value=parsed.netloc, to_ids=True)
        if parsed.path and len(parsed.path) > 1:
            obj.add_attribute("resource_path", value=parsed.path, to_ids=False)
        if parsed.query:
            obj.add_attribute("query_string", value=parsed.query, to_ids=False)

        return obj

    def _build_domain_ip_object(self, target: str, dns_ips: List[str]):
        """Object 2 — domain → resolved IPs (domain-ip object)."""

        parsed = urlparse(target)
        domain = parsed.netloc if parsed.netloc else target

        obj = MISPObject("domain-ip")
        obj.comment = "Domain to IP resolution from scan"
        obj.add_attribute("domain", value=domain, to_ids=True)
        seen = set()
        for ip in dns_ips:
            if ip and ip not in seen:
                obj.add_attribute("ip", value=ip, to_ids=True)
                seen.add(ip)
        return obj

    def _build_whois_object(self, whois_details: Dict[str, Any]):
        """Object 3 — WHOIS registration details (whois object)."""

        obj = MISPObject("whois")
        obj.comment = "WHOIS registration data"

        registrar = whois_details.get("registrar")
        creation = whois_details.get("creation_date")
        age_days = whois_details.get("domain_age_days")
        nameservers = whois_details.get("nameservers", [])

        if registrar:
            obj.add_attribute("registrar", value=str(registrar), to_ids=False)
        if creation:
            obj.add_attribute("creation-date", value=str(creation), to_ids=False)
        if age_days is not None:
            obj.add_attribute(
                "text", value=f"Domain age: {age_days} days", to_ids=False
            )
        if isinstance(nameservers, list):
            for ns in nameservers[:4]:
                if ns:
                    obj.add_attribute("nameserver", value=str(ns), to_ids=False)

        return obj

    def _build_link_analysis_object(
        self, details: Dict[str, Any], verdict: str
    ):
        """Object 4 — link analysis / redirect chain (annotation object)."""

        ips = details.get("resolved_ips", []) or []
        seen = set()
        uniq_ips = [ip for ip in ips if ip not in seen and not seen.add(ip)]
        ip_str = ", ".join(uniq_ips[:10])
        if len(uniq_ips) > 10:
            ip_str += f" (+{len(uniq_ips) - 10} more)"

        lines = [
            f"Verdict: {verdict}",
            f"Original URL: {details.get('original_url', '')}",
            f"Final URL: {details.get('final_url', '')}",
            f"Redirects: {details.get('redirect_count', 0)}",
            f"Domain change: {'yes' if details.get('domain_changed') else 'no'}",
            f"Status code: {details.get('status_code', 'n/a')}",
            f"Resolved IPs: {ip_str if ip_str else 'none'}",
            f"Shortener detected: {'yes' if details.get('contains_shorteners') else 'no'}",
            f"Blocked page: {'yes' if details.get('is_blocked') else 'no'}",
        ]

        obj = MISPObject("annotation")
        obj.comment = "HTTP redirect chain and DNS resolution analysis"
        obj.add_attribute("text", value="\n".join(lines), to_ids=False)
        obj.add_attribute("type", value="link-analysis", to_ids=False)
        return obj

    def _build_yara_object(self, yara_details: Dict[str, Any]):
        """Object 5 — YARA pattern matches (annotation object)."""

        summary = yara_details.get("scan_summary", "No pattern matches")
        patterns = yara_details.get("patterns_matched", []) or []
        rules = yara_details.get("matched_rules", []) or []

        lines = [f"Summary: {summary}"]
        if rules:
            lines.append("Rules matched: " + ", ".join(str(r) for r in rules[:10]))
        if patterns:
            lines.append("Patterns:")
            for p in patterns[:5]:
                if isinstance(p, str) and p:
                    lines.append(f"  - {p}")

        obj = MISPObject("annotation")
        obj.comment = "YARA behavioral analysis results"
        obj.add_attribute("text", value="\n".join(lines), to_ids=False)
        obj.add_attribute("type", value="yara-scan", to_ids=False)
        return obj

    def _build_threat_intel_object(self, threat_intel_summary: List[str]):
        """Object 6 — per-provider verdicts (annotation object)."""

        lines = [f"- {seg}" for seg in threat_intel_summary if isinstance(seg, str) and seg]
        text = "Threat Intel:\n" + ("\n".join(lines) if lines else "None")

        obj = MISPObject("annotation")
        obj.comment = "Consolidated threat intelligence vendor verdicts"
        obj.add_attribute("text", value=text, to_ids=False)
        obj.add_attribute("type", value="threat-intel", to_ids=False)
        return obj

    def _build_assessment_object(
        self,
        threat_count: int,
        total_providers: int,
        clean_providers: int,
        threat_score: int,
        session_id: str,
        scoring_data: Dict[str, Any],
    ):
        """Object 7 — overall assessment (annotation object)."""

        verdict = "CRITICAL" if threat_score >= 70 else "SUSPICIOUS" if threat_score >= 40 else "CLEAN"
        breakdown = scoring_data.get("score_breakdown", {})
        contributing = ", ".join(
            f"{k}:{v}" for k, v in breakdown.items() if v
        ) if isinstance(breakdown, dict) else ""

        lines = [
            f"Verdict: {verdict}",
            f"Threat score: {threat_score}/100",
            f"Providers flagged: {threat_count}/{total_providers}",
            f"Clean providers: {clean_providers}/{total_providers}",
            f"Session ID: {session_id}",
        ]
        if contributing:
            lines.append(f"Score contributors: {contributing}")

        obj = MISPObject("annotation")
        obj.comment = "Overall threat assessment summary"
        obj.add_attribute("text", value="\n".join(lines), to_ids=False)
        obj.add_attribute("type", value="assessment", to_ids=False)
        return obj

    # -------------------------------------------------------------------------
    # Main entry point
    # -------------------------------------------------------------------------

    def create_event(
        self, target: str, results: List[ProviderResult], session_id: str
    ) -> Optional[Dict[str, Any]]:
        """Create a structured MISP event from scan results using MISPObject instances."""
        threat_results = [r for r in results if r.is_threat]
        if not threat_results:
            return None

        self._initialize_misp_client()

        try:

            from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer

            scoring_data = UnifiedThreatScorer().calculate_threat_score(results)
            threat_score = scoring_data["final_score"]
            threat_count = len(threat_results)
            total_providers = len(results)
            clean_providers = total_providers - threat_count

            # ---- Create the event ----------------------------------------
            event = MISPEvent()
            event.info = f"Threat Analysis: {target} [CRITICAL] - SID: {session_id}"
            event.threat_level_id = 1  # High
            event.analysis = 1  # Ongoing
            event.distribution = 0  # Your organisation only

            misp_event = self._misp_client.add_event(event, pythonify=True)
            if not misp_event or hasattr(misp_event, "errors"):
                raise Exception("Failed to create MISP event")

            event_id = misp_event.id
            event_uuid = getattr(misp_event, "uuid", None)

            # ---- Collect data from provider results -----------------------
            dns_ips: List[str] = []
            whois_details: Dict[str, Any] = {}
            link_analyzer_details: Dict[str, Any] = {}
            link_analyzer_verdict = "Unknown"
            yara_details: Dict[str, Any] = {}
            threat_intel_summary: List[str] = []
            has_yara = False
            has_link_analyzer = False

            for result in results:
                pname = getattr(result, "provider", "").lower()
                det = result.details if isinstance(getattr(result, "details", None), dict) else {}

                if pname in ("link_analyzer", "dns"):
                    ips = det.get("resolved_ips", [])
                    if ips:
                        dns_ips.extend(ips)

                if pname == "link_analyzer":
                    has_link_analyzer = True
                    link_analyzer_details = det
                    tl = getattr(result, "threat_level", None)
                    tl_val = getattr(tl, "value", "unknown") if tl else "unknown"
                    link_analyzer_verdict = tl_val.capitalize() if isinstance(tl_val, str) else "Unknown"
                    continue  # don't add to threat_intel_summary

                if pname == "whois":
                    whois_details = det

                if pname == "yara":
                    has_yara = True
                    yara_details = det

                # Build per-provider threat intel summary
                tl = getattr(result, "threat_level", None)
                tl_val = getattr(tl, "value", None)
                verdict_map = {
                    "malicious": "Malicious", "critical": "Critical",
                    "suspicious": "Suspicious", "safe": "Safe",
                    "unknown": "Unknown", "error": "Error",
                }
                base_verdict = verdict_map.get(tl_val, "Unknown")

                if pname == "virustotal" and det:
                    mal = det.get("malicious_count", 0)
                    total = det.get("total_engines", 0)
                    segment = f"VT: Malicious ({mal}/{total})" if mal else f"VT: Clean ({total} engines)"
                    cats = det.get("categories") or det.get("categories_vt") or []
                    if isinstance(cats, list) and cats:
                        unique_cats = sorted({c.strip().lower() for c in cats if isinstance(c, str) and c})
                        if unique_cats:
                            segment += f" [Categories: {', '.join(unique_cats)}]"
                    threat_intel_summary.append(segment)

                elif pname == "whalebone" and det:
                    max_acc = det.get("max_accuracy", det.get("accuracy", 0)) or 0
                    threat_types = [t for t in (det.get("threat_types") or []) if isinstance(t, str)]
                    tt_str = ", ".join(sorted(set(threat_types))) if threat_types else ""
                    cats = det.get("categories", []) or []
                    v = base_verdict
                    base = f"WHALEBONE: {v} ({tt_str}; Max accuracy: {int(max_acc)}%)" if tt_str else f"WHALEBONE: {v} (Max accuracy: {int(max_acc)}%)"
                    if cats:
                        cats_str = ", ".join(sorted({c for c in cats if isinstance(c, str)}))
                        threat_intel_summary.append(f"{base} [Categories: {cats_str}]")
                    else:
                        threat_intel_summary.append(base)

                elif pname == "google_sb" and result.is_threat:
                    sb_types = det.get("threat_types", [])
                    threat_intel_summary.append(
                        f"GOOGLE_SB: Malicious ({', '.join(sb_types)})" if sb_types else "GOOGLE_SB: Malicious"
                    )

                elif pname == "abuseipdb" and det:
                    confidence = det.get("abuse_confidence", det.get("abuseConfidencePercentage", 0))
                    if confidence:
                        threat_intel_summary.append(f"ABUSEIPDB: {det.get('verdict', 'Suspicious')} (Confidence: {confidence}%)")
                    else:
                        threat_intel_summary.append(f"ABUSEIPDB: {base_verdict}")

                elif pname == "yara":
                    matched = det.get("matched_rules", []) or []
                    if matched:
                        threat_intel_summary.append(f"YARA: {base_verdict} (Rules: {', '.join(str(r) for r in matched[:5])})")
                    else:
                        threat_intel_summary.append(f"YARA: {base_verdict}")

                else:
                    threat_intel_summary.append(f"{result.provider.upper()}: {base_verdict}")

            # ---- Add MISPObjects to event --------------------------------

            # 1) URL object
            self._add_object(event_id, self._build_url_object(target, threat_score), "url")

            # 2) domain-ip object (only if we have IPs)
            if dns_ips:
                self._add_object(event_id, self._build_domain_ip_object(target, dns_ips), "domain-ip")

            # 3) WHOIS object
            if whois_details:
                self._add_object(event_id, self._build_whois_object(whois_details), "whois")

            # 4) Link analysis annotation
            if has_link_analyzer and link_analyzer_details:
                self._add_object(
                    event_id,
                    self._build_link_analysis_object(link_analyzer_details, link_analyzer_verdict),
                    "link-analysis annotation",
                )

            # 5) YARA annotation
            if has_yara:
                self._add_object(event_id, self._build_yara_object(yara_details), "yara annotation")

            # 6) Threat intel annotation
            if threat_intel_summary:
                self._add_object(
                    event_id,
                    self._build_threat_intel_object(threat_intel_summary),
                    "threat-intel annotation",
                )

            # 7) Assessment annotation
            self._add_object(
                event_id,
                self._build_assessment_object(
                    threat_count, total_providers, clean_providers,
                    threat_score, session_id, scoring_data,
                ),
                "assessment annotation",
            )

            # ---- Tags ----------------------------------------------------
            self._misp_client.tag(misp_event, "tlp:white")
            self._misp_client.tag(misp_event, f"urlchecker:score={threat_score}")
            self._misp_client.tag(misp_event, f"urlchecker:threats={threat_count}")
            self._misp_client.tag(misp_event, f"urlchecker:providers={total_providers}")

            if threat_count == 1:
                self._misp_client.tag(misp_event, "confidence:single-source")
            elif threat_count >= 2:
                self._misp_client.tag(misp_event, "confidence:multi-source")
            if total_providers >= 5:
                self._misp_client.tag(misp_event, "coverage:comprehensive")

            self._logger.info(
                f"Created MISP event {event_id} (UUID: {event_uuid}) for {target}"
            )
            return {"event_id": event_id, "uuid": event_uuid}

        except Exception as e:
            self._logger.error(f"Failed to create MISP event: {e}")
            return None

    def _add_object(self, event_id, misp_obj, label: str):
        """Add a MISPObject to an event, logging failures without raising."""
        if not getattr(misp_obj, "attributes", None):
            self._logger.debug(f"Skipping empty MISP object '{label}'")
            return
        try:
            result = self._misp_client.add_object(event_id, misp_obj)
            if isinstance(result, dict) and "errors" in result:
                self._logger.warning(f"MISP object '{label}' returned errors: {result['errors']}")
            elif not result:
                self._logger.warning(f"MISP object '{label}' returned empty response")
        except Exception as e:
            self._logger.error(f"Failed to add MISP object '{label}': {e}")
