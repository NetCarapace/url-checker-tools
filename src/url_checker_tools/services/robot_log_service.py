"""Robot mode log files: synthesis (.log) and detailed (.dlog) JSON."""

import json
from datetime import datetime, timezone
from typing import Any, List, Optional

from url_checker_tools.config.logging_config import WorkflowLogger


class RobotLogBuilder:
    """Builds and writes the dual robot mode log files for one session."""

    def __init__(self, session_id: str, logger: Optional[WorkflowLogger]):
        self.session_id = session_id
        self.logger = logger

    def write(
        self,
        target: str,
        results: List[Any],
        synthesis_json: str,
        misp_data: dict = None,
    ) -> None:
        """Create comprehensive dual log files for robot mode matching old format."""
        try:
            from urllib.parse import urlparse

            # Create comprehensive target info
            target_info = self._get_target_info(target)

            # Create comprehensive synthesis log (.log)
            synthesis_data = self._create_comprehensive_synthesis(
                target, results, synthesis_json, target_info, misp_data
            )
            synthesis_json_final = json.dumps(
                synthesis_data, indent=2, ensure_ascii=False
            )

            # Create comprehensive detailed log (.dlog)
            detailed_data = self._create_comprehensive_detailed(
                target, results, target_info, misp_data
            )
            detailed_json = json.dumps(detailed_data, indent=2, ensure_ascii=False)

            # Create the dual log files
            synthesis_path, detailed_path = self.logger.create_dual_logs(
                target, synthesis_json_final, detailed_json
            )

            print(f"[INFO] Robot logs created:")
            print(f"  Synthesis: {synthesis_path}")
            print(f"  Detailed: {detailed_path}")

        except Exception as e:
            print(f"[ERROR] Failed to create robot logs: {e}")

    def _get_target_info(self, target: str) -> dict:
        """Get comprehensive target information matching old format."""
        import hashlib
        from urllib.parse import urlparse

        # Detect target type
        target_type = "url" if target.startswith(("http://", "https://")) else "domain"

        # Normalize for hashing (lowercase domain, preserve path case)
        if target_type == "url":
            try:
                parsed = urlparse(target)
                normalized = (
                    f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
                )
                if parsed.query:
                    normalized += f"?{parsed.query}"
                normalized = (
                    normalized.rstrip("/") if parsed.path in ("", "/") else normalized
                )
            except:
                normalized = target.lower()
        else:
            normalized = target.lower()

        target_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        info = {
            "original": target,
            "normalized": normalized,
            "type": target_type,
            "hash": target_hash,
        }

        # Add URL-specific info
        if target_type == "url":
            try:
                parsed = urlparse(target)
                info.update(
                    {
                        "scheme": parsed.scheme,
                        "domain": parsed.netloc,
                        "path": parsed.path,
                        "query": parsed.query,
                    }
                )

                # Add DNS resolution if available
                dns_results = [
                    r
                    for r in getattr(self, "_all_results", [])
                    if hasattr(r, "provider")
                    and r.provider.lower() in ["link_analyzer", "dns"]
                ]
                if (
                    dns_results
                    and hasattr(dns_results[0], "details")
                    and dns_results[0].details
                ):
                    resolved_ips = dns_results[0].details.get("resolved_ips", [])
                    if resolved_ips:
                        info.update(
                            {
                                "resolved_ips": resolved_ips[:5],  # First 5 IPs
                                "dns_resolution": {
                                    "ipv4_addresses": [
                                        ip for ip in resolved_ips if ":" not in ip
                                    ],
                                    "ipv6_addresses": [
                                        ip for ip in resolved_ips if ":" in ip
                                    ],
                                    "resolution_timestamp": datetime.now(
                                        timezone.utc
                                    ).isoformat(),
                                    "total_ips": len(resolved_ips),
                                },
                                "url_change": "No",  # Default, could be enhanced
                            }
                        )
            except:
                pass

        return info

    def _create_comprehensive_synthesis(
        self,
        target: str,
        results: List[Any],
        synthesis_json: str,
        target_info: dict,
        misp_data: dict = None,
    ) -> dict:
        """Create comprehensive synthesis log matching old format."""
        try:
            # Parse existing synthesis if available
            synthesis_content = json.loads(synthesis_json) if synthesis_json else {}
        except:
            synthesis_content = {}

        # Create session metadata
        session_metadata = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_info": target_info,
        }

        # Add MISP event information if available
        if misp_data:
            session_metadata["misp_event"] = misp_data

        # Create enhanced synthesis with provider breakdown, scoring, and metadata
        enhanced_synthesis = self._create_enhanced_synthesis_content(
            results, synthesis_content
        )

        return {"session_metadata": session_metadata, "synthesis": enhanced_synthesis}

    def _create_comprehensive_detailed(
        self, target: str, results: List[Any], target_info: dict, misp_data: dict = None
    ) -> dict:
        """Create comprehensive detailed log matching old format."""
        # Session metadata (same as synthesis)
        session_metadata = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_info": target_info,
        }

        # Add MISP event information if available
        if misp_data:
            session_metadata["misp_event"] = misp_data

        # Detailed results with full raw responses
        detailed_results = {
            "target": target,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "provider_results": [],
        }

        for result in results:
            if hasattr(result, "provider"):
                # Create comprehensive provider result entry
                # Build raw response with special handling for MISP to avoid huge dumps
                raw_resp = self._get_raw_response(result)
                if (
                    isinstance(getattr(result, "provider", ""), str)
                    and result.provider.lower() == "misp"
                ):
                    # Remove nested heavy payloads and keep only concise fields
                    if isinstance(raw_resp, dict):
                        # Drop nested 'raw_response' and limit 'sample_events'
                        raw_resp = {
                            k: v for k, v in raw_resp.items() if k != "raw_response"
                        }
                        if isinstance(raw_resp.get("sample_events"), list):
                            raw_resp["sample_events"] = raw_resp["sample_events"][:3]

                result_entry = {
                    "provider": result.provider,
                    "status": (
                        ("unavailable" if result.is_unavailable else "error")
                        if result.is_error
                        else "threat" if result.is_threat else "clean"
                    ),
                    "threat_detected": getattr(result, "is_threat", False),
                    "threat_type": self._serialize_enum(
                        getattr(result, "threat_level", None)
                    ),
                    "confidence": self._format_confidence(result),
                    "tags": getattr(result, "tags", []),
                    "error_message": getattr(result, "error_message", None),
                    "raw_response": raw_resp,
                }
                detailed_results["provider_results"].append(result_entry)

        return {"session_metadata": session_metadata, "results": detailed_results}

    def _create_enhanced_synthesis_content(
        self, results: List[Any], existing_synthesis: dict
    ) -> dict:
        """Create enhanced synthesis content with provider breakdown and scoring."""
        # Start with existing synthesis or create basic structure
        synthesis = existing_synthesis.copy() if existing_synthesis else {}

        # Use unified scoring system for consistency with CLI display
        from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer

        scorer = UnifiedThreatScorer()
        scoring_data = scorer.calculate_threat_score(results)

        # Add comprehensive provider breakdown
        providers_summary = {}
        whois_info = {}
        link_analysis = {}
        yara_info = {}
        metadata_analysis = {
            "behavioral_anomalies": [],
            "risk_indicators": [],
            "confidence_score": 0.7,
            "cross_validation_status": "medium_consistency",
        }

        # Process each provider result
        threat_count = 0
        total_providers = len([r for r in results if hasattr(r, "provider")])

        for result in results:
            if not hasattr(result, "provider"):
                continue

            provider = result.provider.lower()
            is_threat = getattr(result, "is_threat", False)
            details = getattr(result, "details", {})

            # Providers that did not run get no verdict and no provider-specific section
            if result.is_error:
                providers_summary[provider] = (
                    "Unavailable" if result.is_unavailable else "Error"
                )
                continue

            if is_threat:
                threat_count += 1

            # Provider-specific synthesis
            if provider == "whois":
                if details:
                    age_days = details.get("domain_age_days")
                    # Fallback: compute age if provider did not populate it
                    if (age_days is None or age_days == 0) and details.get(
                        "creation_date"
                    ):
                        from datetime import datetime, timezone

                        creation_str = details.get("creation_date")
                        # Try several formats commonly seen in WHOIS
                        fmts = [
                            "%Y-%m-%dT%H:%M:%SZ",
                            "%Y-%m-%dT%H:%M:%S%z",
                            "%Y-%m-%d %H:%M:%S%z",
                            "%Y-%m-%d %H:%M:%S",
                            "%Y-%m-%d",
                            "%d-%b-%Y",
                            "%d-%b-%Y %H:%M:%S %Z",
                            "%Y.%m.%d %H:%M:%S",
                            "%Y.%m.%d",
                            "%Y/%m/%d",
                            "%d.%m.%Y",
                        ]
                        dt = None
                        for part in [
                            p.strip()
                            for p in str(creation_str).replace("\t", " ").split(",")
                        ]:
                            for fmt in fmts:
                                try:
                                    dt = datetime.strptime(part, fmt)
                                    if dt.tzinfo is None:
                                        dt = dt.replace(tzinfo=timezone.utc)
                                    break
                                except Exception:
                                    continue
                            if dt:
                                break
                        if dt:
                            delta = datetime.now(timezone.utc) - dt.astimezone(
                                timezone.utc
                            )
                            age_days = max(0, delta.days)
                        else:
                            age_days = 0
                    whois_info = {
                        "is_active": details.get("is_active", True),
                        "age": age_days or 0,
                        "domain": details.get("domain_name", ""),
                        "status": details.get("status", "active"),
                    }
                    providers_summary["whois"] = (
                        f"Age: {age_days or 0} days; Registrar: {details.get('registrar', 'Unknown')}"
                    )

            elif provider == "virustotal":
                if details:
                    malicious = details.get("malicious_count", 0)
                    total = details.get("total_engines", 0)
                    base = (
                        f"Malicious ({malicious}/{total})"
                        if malicious > 0
                        else f"Harmless ({total - malicious} clean engines)"
                    )
                    # Append categories if available
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
                            base = f"{base} | Categories: {', '.join(unique_cats)}"
                    providers_summary["virustotal"] = base

            elif provider == "whalebone":
                if details:
                    threat_types = details.get("threat_types", []) or []
                    # Deduplicate categories and limit length for readability
                    categories = details.get("categories", []) or []
                    unique_categories = []
                    seen_cat = set()
                    for c in categories:
                        if isinstance(c, str) and c not in seen_cat:
                            unique_categories.append(c)
                            seen_cat.add(c)
                    max_acc = details.get("max_accuracy", 0)

                    # Determine base verdict text
                    if is_threat:
                        level = (
                            getattr(result.threat_level, "value", "suspicious")
                            if hasattr(result, "threat_level")
                            else "suspicious"
                        )
                        base = (
                            "Malicious"
                            if level in ["malicious", "critical"]
                            else "Suspicious"
                        )
                    else:
                        base = "Clean"

                    parts = [base]
                    if threat_types:
                        parts.append(
                            f"Threats: {', '.join(threat_types)} (max {max_acc}%)"
                        )
                    if unique_categories:
                        parts.append(f"Categories: {', '.join(unique_categories)}")

                    providers_summary["whalebone"] = " | ".join(parts)
                else:
                    providers_summary["whalebone"] = "Clean"

            elif provider == "misp":
                # Include MISP summary in synthesis
                events_found = 0
                if isinstance(details, dict):
                    events_found = details.get("events_found", 0)
                if is_threat and events_found:
                    providers_summary["misp"] = f"Threats Found ({events_found} events)"
                else:
                    providers_summary["misp"] = "Clean"

            elif provider == "google_sb":
                providers_summary["google_sb"] = "Malicious" if is_threat else "Safe"

            elif provider == "link_analyzer":
                if details:
                    redirects = details.get("redirect_count", 0)
                    final_url = details.get("final_url", "")
                    link_analysis = {
                        "redirects": redirects,
                        "domain_change": details.get("domain_changed", False),
                        "is_blocked": details.get("is_blocked", False),
                        "final_url": final_url,
                        "dns_resolved": bool(details.get("resolved_ips")),
                        "security_downgrades": 0,
                        "contains_shorteners": details.get(
                            "contains_shorteners", False
                        ),
                        "suspicious_patterns": [],
                    }
                    # Include verdict in providers summary for clarity
                    tl_val = getattr(
                        getattr(result, "threat_level", None), "value", "safe"
                    )
                    if tl_val in ["malicious", "critical"]:
                        la_verdict = "Malicious"
                    elif tl_val == "suspicious":
                        la_verdict = "Suspicious"
                    elif tl_val == "error":
                        la_verdict = "Error"
                    else:
                        la_verdict = "Safe"
                    dom_change = details.get("domain_changed", False)
                    extras = []
                    extras.append(f"{redirects} redirect(s)")
                    if dom_change:
                        extras.append("domain change: yes")
                    providers_summary["link_analyzer"] = (
                        f"{la_verdict} | " + " | ".join(extras)
                    )

            elif provider == "yara":
                yara_info = {
                    "type": "clean" if not is_threat else "threat",
                    "redirects": 0,
                    "url_shorteners": 0,
                    "domain_change": None,
                    "security_downgrades": 0,
                    "download_links": 0,
                    "flags": [],
                }
                if details:
                    patterns = details.get("scan_summary", "No pattern matches")
                    providers_summary["yara"] = patterns

            elif provider in ["abuseipdb", "abuse_ip_db"]:
                if details:
                    confidence = details.get(
                        "abuse_confidence", details.get("abuseConfidencePercentage", 0)
                    )
                    reports = details.get(
                        "report_count", details.get("totalReports", 0)
                    )
                    providers_summary["abuseipdb"] = (
                        f"High Risk ({confidence}%)"
                        if is_threat and confidence
                        else f"Low Risk ({reports} reports)"
                    )

            # Ensure every provider has an entry even if no provider-specific summary was set
            if provider not in providers_summary:
                if getattr(result, "is_error", False):
                    providers_summary[provider] = "Error"
                else:
                    providers_summary[provider] = "Malicious" if is_threat else "Safe"

        # Use unified scoring data for consistency
        threat_score = scoring_data["final_score"]
        verdict = scoring_data["verdict"]

        # Build comprehensive synthesis
        enhanced = {
            "whois": whois_info,
            "providers": providers_summary,
            "metadata_analysis": metadata_analysis,
        }

        # Add conditional sections first
        if link_analysis:
            enhanced["link_analysis"] = link_analysis
        if yara_info:
            enhanced["yara"] = yara_info

        # Always add result section LAST to ensure proper ordering in logs
        enhanced["result"] = {
            "verdict": verdict,
            "threat_score": threat_score,
            "metadata_confidence": 0.7,
            "cross_validation_status": "medium_consistency",
        }

        return enhanced

    def _format_confidence(self, result) -> str:
        """Format confidence information for logs."""
        if hasattr(result, "confidence") and result.confidence is not None:
            if isinstance(result.confidence, (int, float)):
                return f"{result.confidence:.2f}"
            return str(result.confidence)
        elif hasattr(result, "details") and result.details:
            # Extract confidence from details
            details = result.details
            if "confidence" in details:
                return str(details["confidence"])
            elif "accuracy" in details:
                return f"accuracy: {details['accuracy']}%"
        return "medium"

    def _serialize_enum(self, value):
        """Serialize enum values for JSON compatibility."""
        if hasattr(value, "value"):
            return value.value
        elif hasattr(value, "name"):
            return value.name
        return str(value) if value is not None else None

    def _get_raw_response(self, result) -> dict:
        """Get raw response data for detailed logs."""
        if hasattr(result, "details") and result.details:
            return result.details
        elif hasattr(result, "raw_response"):
            return result.raw_response
        else:
            # Create basic raw response
            return {
                "source": getattr(result, "provider", "unknown"),
                "status": (
                    "completed" if not getattr(result, "is_error", False) else "error"
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
