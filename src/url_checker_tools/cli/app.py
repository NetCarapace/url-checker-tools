#!/usr/bin/env python3
"""
Comprehensive URLChecker-Tools - Full-featured CLI wrapper to various cheker tools

Combines the new clean provider system with complete backward compatibility
for all original CLI options and functionality.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, List, Optional

from url_checker_tools.cli.output_service import OutputService
from url_checker_tools.config.logging_config import WorkflowLogger, set_session_id
from url_checker_tools.output.formatters import get_formatter
from url_checker_tools.services.provider_registry import ProviderRegistry
from url_checker_tools.services.scan_request import ScanRequest
from url_checker_tools.workflows.orchestrator import WorkflowOrchestrator


class URLCheckerCLI:
    """Comprehensive CLI that integrates clean provider system with full functionality."""

    def __init__(self):
        """Initialize CLI with available providers."""
        self.registry = ProviderRegistry()

        self.logger: Optional[WorkflowLogger] = None
        self.session_id: Optional[str] = None

    def create_argument_parser(self) -> argparse.ArgumentParser:
        """Create comprehensive argument parser with all legacy options."""
        parser = argparse.ArgumentParser(
            description="Comprehensive URL and domain threat intelligence checker",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s example.com                          # Baseline scan (whois + link_analyzer)
  %(prog)s --providers virustotal,google_sb example.com  # Baseline + additional providers
  %(prog)s --all example.com                   # All available providers
  %(prog)s --list-providers                   # Show available providers

  # Robot mode for automation
  %(prog)s --robot --sid session123 example.com
  %(prog)s --robot --misp --sid session123 example.com        # Query MISP for existing events
  %(prog)s --robot --misp-report --sid session123 example.com # Create new MISP events
            """,
        )

        parser.add_argument("target", nargs="?", help="URL or domain to check")

        # Modern provider selection
        provider_group = parser.add_mutually_exclusive_group()
        provider_group.add_argument(
            "--providers",
            help="Comma-separated list of additional providers to run alongside baseline (whois,link_analyzer)",
        )
        provider_group.add_argument(
            "--all", action="store_true", help="Use all available providers"
        )

        # Output format options
        parser.add_argument(
            "--format",
            choices=["human", "json", "synthesis"],
            default="human",
            help="Output format",
        )
        parser.add_argument(
            "--raw",
            action="store_true",
            help="Output raw JSON (deprecated: use --format json)",
        )

        # YARA configuration
        parser.add_argument(
            "--yara-rules",
            nargs="*",
            default=[],
            help="Specific YARA rule files or directories to use",
        )
        parser.add_argument(
            "--yara-timeout",
            type=int,
            default=30,
            help="Timeout for fetching content (default: 30s)",
        )
        parser.add_argument(
            "--yara-max-bytes",
            type=int,
            default=10485760,  # 10MB
            help="Maximum bytes to scan (default: 10MB)",
        )

        # File scanning
        parser.add_argument(
            "--auto-scan-files",
            action="store_true",
            help="Automatically scan detected download files",
        )
        parser.add_argument(
            "--download",
            action="store_true",
            help="Enable file download scanning (placeholder)",
        )

        # Session and logging options
        parser.add_argument(
            "--sid",
            "--session-id",
            dest="session_id",
            help="Session ID for tracking and logging",
        )
        parser.add_argument(
            "--log",
            action="store_true",
            help="Save output to structured log file",
        )
        parser.add_argument(
            "--robot",
            action="store_true",
            help="Automation mode: minimal output, dual logging (.log/.dlog files). Requires --sid.",
        )
        parser.add_argument(
            "--score",
            action="store_true",
            help="Include basic threat score result",
        )
        parser.add_argument(
            "--score-detail",
            action="store_true",
            help="Include detailed scoring calculation breakdown (supersedes --score)",
        )

        # MISP reporting integration
        parser.add_argument(
            "--misp-report",
            action="store_true",
            help="Enable MISP threat intelligence reporting (create new MISP events from scan results)",
        )

        # Workflow options (new)
        parser.add_argument(
            "--workflow",
            choices=["fast", "complete", "reputation"],
            help="Use Celery workflow for distributed scanning",
        )

        # Provider information
        parser.add_argument(
            "--list-providers",
            action="store_true",
            help="List all available providers and exit",
        )
        parser.add_argument(
            "--providers-status",
            action="store_true",
            help="Show detailed provider status and exit",
        )

        # General options
        parser.add_argument(
            "--verbose", action="store_true", help="Enable verbose output"
        )

        return parser

    def setup_logging(self, args) -> None:
        """Set up logging based on CLI arguments."""
        if args.session_id:
            self.session_id = args.session_id
            set_session_id(args.session_id)
        else:
            self.session_id = str(uuid.uuid4())[:8]

        if args.log or args.robot:
            self.logger = WorkflowLogger(session_id=self.session_id)

    def scan_direct(
        self,
        request: ScanRequest,
        misp_reporting_enabled: bool = False,
    ) -> List[Any]:
        """Perform direct scanning with specified providers."""
        target = request.target
        providers = request.providers
        results = []

        # Setup output formatting
        output_format = "json" if request.raw else request.format
        formatter = get_formatter(output_format)

        # Robot mode output handling
        if request.robot:
            # Always show SID first in robot mode
            print(f"SID: {self.session_id}")

            if request.verbose:
                print(f"[INFO] Target: {target}")
                print(f"[INFO] Enabled providers: {', '.join(providers)}")
            else:
                # Non-verbose: show minimal scanning status
                active_providers = []
                for provider_name in providers:
                    provider_class = self.registry.get(provider_name)
                    if provider_class:
                        try:
                            with provider_class() as provider:
                                if provider.is_available():
                                    active_providers.append(provider_name)
                        except Exception:
                            pass
                if active_providers:
                    print(f"[SCAN] Checking: {', '.join(active_providers)}")
        else:
            print(f"Scanning {target}...")
            if request.verbose:
                print(f"[INFO] Enabled providers: {', '.join(providers)}")

        # Scan with each provider
        for provider_name in providers:
            provider_class = self.registry.get(provider_name)
            if not provider_class:
                if not request.robot:
                    print(f"Unknown provider: {provider_name}")
                continue

            if not request.robot:
                print(f"Running {provider_name}...")
                if request.verbose:
                    print(f"[INFO] Starting {provider_name} scan...")

            try:
                # Initialize provider (configuration auto-loaded from enum)
                provider = provider_class()

                # Set verbose flag for base config if possible
                if hasattr(provider.config, "verbose"):
                    provider.config.verbose = request.verbose

                with provider:
                    if provider.is_available():
                        # In robot mode, suppress individual provider verbose messages during scanning
                        if request.verbose and not request.robot:
                            print(
                                f"[INFO] {provider_name} provider is available, starting scan..."
                            )

                        result = provider.scan_with_timing(target)
                        results.append(result)

                        # Log to file if logging enabled
                        if self.logger:
                            self.logger.log_provider_result(result)

                        # Verbose execution details (suppress in robot mode during scanning)
                        if request.verbose and not request.robot:
                            exec_time = getattr(result, "execution_time", 0) or 0
                            print(
                                f"[INFO] {provider_name} completed in {exec_time:.2f}s - {'Threat' if result.is_threat else 'Safe'}"
                            )

                        # Display result (unless in robot mode)
                        if not request.robot:
                            print(formatter.format_provider_result(result))
                    else:
                        if not request.robot:
                            print(f"  {provider_name} is not properly configured")
                        # In robot mode, suppress availability warnings during scanning
                        if request.verbose and not request.robot:
                            print(
                                f"[WARNING] {provider_name} provider availability check failed"
                            )
                        # In robot mode, record an error result so summaries include all enabled providers
                        if request.robot:
                            from url_checker_tools.core.results import (
                                ProviderResult,
                                ThreatLevel,
                            )

                            results.append(
                                ProviderResult(
                                    provider=provider_name,
                                    target=target,
                                    is_threat=False,
                                    threat_level=ThreatLevel.ERROR,
                                    confidence=0.0,
                                    details={
                                        "status": "unavailable",
                                        "reason": "provider not configured",
                                    },
                                    timestamp=None,
                                    execution_time=0.0,
                                    error_message=f"{provider_name} not available",
                                )
                            )

            except Exception as e:
                error_msg = f"{provider_name} scan failed: {e}"
                if not request.robot:
                    print(f"   {error_msg}")
                if request.verbose:
                    print(f"[ERROR] {provider_name} exception details: {str(e)[:200]}")
                if self.logger:
                    self.logger.log_error(target, provider_name, error_msg)
                # In robot mode, append an error result so it's reflected in summaries and scoring
                if request.robot:
                    from url_checker_tools.core.results import (
                        ProviderResult,
                        ThreatLevel,
                    )

                    results.append(
                        ProviderResult(
                            provider=provider_name,
                            target=target,
                            is_threat=False,
                            threat_level=ThreatLevel.ERROR,
                            confidence=0.0,
                            details={"status": "error", "message": str(e)[:500]},
                            timestamp=None,
                            execution_time=0.0,
                            error_message=error_msg,
                        )
                    )

        # Handle file scanning if enabled
        if (request.auto_scan_files or request.download) and results:
            self._handle_file_scanning(request, results)

        # Summary with optional scoring
        if not request.robot:
            threat_count = sum(1 for r in results if r.is_threat and not r.is_error)
            safe_count = sum(1 for r in results if not r.is_threat and not r.is_error)
            error_count = sum(1 for r in results if r.is_error)

            print(
                f"\nSummary: {len(results)} providers, {threat_count} threats detected"
            )

            # Scoring breakdown if requested
            if (request.score or request.score_detail) and results:
                from url_checker_tools.analysis.unified_scorer import (
                    UnifiedThreatScorer,
                )

                scorer = UnifiedThreatScorer()
                scoring_data = scorer.calculate_threat_score(results)

                # --score-detail supersedes --score
                if request.score_detail:
                    print(f"\n{scorer.format_scoring_details(scoring_data)}")
                else:
                    # Basic score output - use appropriate format
                    score_format = "json" if output_format == "json" else "human"
                    print(f"\n{scorer.format_basic_score(scoring_data, score_format)}")

                # Log scoring details if logging is enabled
                if self.logger:
                    self.logger.log_synthesis(
                        "manual_scoring",
                        target,
                        {
                            "scoring_system": "simplified_threat_scorer",
                            "scoring_data": scoring_data,
                        },
                    )

            if request.verbose:
                print("[INFO] Provider results breakdown:")
                print(f"  - Safe: {safe_count}")
                print(f"  - Threats: {threat_count}")
                print(f"  - Errors: {error_count}")

        # Robot mode: Add RESULT output and optional verbose summary
        # Robot mode automatically behaves like --format synthesis --score (basic scoring, not detailed)
        if request.robot:
            # Use unified scoring system for robot mode (always enabled)
            from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer

            scorer = UnifiedThreatScorer()
            scoring_data = scorer.calculate_threat_score(results)

            score = scoring_data["final_score"]
            verdict = scoring_data["verdict"]

            print(f"RESULT: {verdict} ({score}/100)")

            # Robot mode: force synthesis format with scoring for log files
            # Skip log creation here if MISP reporting is enabled (logs will be created later with MISP data)
            if self.logger and not misp_reporting_enabled:
                threat_level_map = scorer.get_threat_level_mapping()
                robot_synthesis = {
                    "synthesis": {
                        "threat_level": threat_level_map.get(verdict, "unknown"),
                        "threat_score": score,
                        "verdict": verdict,
                        "confidence": min(1.0, score / 100.0),
                        "providers_checked": scoring_data["provider_count"],
                        "threats_detected": scoring_data["threat_count"],
                        "multi_provider_agreement": scoring_data[
                            "multi_provider_boost"
                        ],
                        "provider_breakdown": scoring_data["provider_breakdown"],
                    }
                }
                robot_synthesis_str = json.dumps(robot_synthesis, indent=2)
                self._create_robot_logs(request.target, results, robot_synthesis_str)

            # Verbose robot mode: show human-readable summary
            if request.verbose:
                self.output.robot_verbose_summary(results, target)

        return results

    def _create_robot_logs(
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
        if "yara" in locals():
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

    def main(self) -> None:
        """Run the command-line interface."""
        parser = self.create_argument_parser()
        args = parser.parse_args()

        # Handle special cases first
        if args.list_providers:
            OutputService.list_providers(self.registry)
            return

        if args.providers_status:
            OutputService.provider_status(self.registry)
            return

        # Apply robot mode flags if robot mode is enabled
        if args.robot:
            try:
                from url_checker_tools.config.robot_config import RobotModeConfig

                RobotModeConfig.apply_robot_flags(args)
            except Exception as e:
                print(f"Warning: Failed to apply robot mode flags: {e}")

        # Validate robot mode requirements (after applying robot flags)
        if args.robot and not args.session_id:
            print("Error: --robot mode requires --sid/--session-id")
            sys.exit(1)

        # Require target for scanning
        if not args.target:
            print("Error: Target URL or domain is required")
            parser.print_help()
            sys.exit(1)

        # Setup logging
        self.setup_logging(args)

        # Determine providers
        providers = self.registry.select(args.providers, args.all, args.robot)
        request = ScanRequest.from_args(args, providers, self.session_id)
        self.output = OutputService(request, self.logger, self._create_robot_logs)

        try:
            if args.workflow:
                # Use Celery workflow
                orchestrator = WorkflowOrchestrator(self.session_id)

                if args.workflow == "fast":
                    workflow_id = orchestrator.scan_url_fast(args.target)
                elif args.workflow == "reputation":
                    workflow_id = orchestrator.scan_domain_reputation(args.target)
                else:
                    workflow_id = orchestrator.scan_url_complete(args.target)

                if not args.robot:
                    print(f"Started workflow {workflow_id} for {args.target}")
                    print("Use 'celery flower' to monitor progress")
            else:
                # Direct scanning
                results = self.scan_direct(
                    request,
                    misp_reporting_enabled=args.misp_report,
                )

                # MISP reporting (if enabled) - do this before output format to capture event ID
                misp_data = None
                if args.misp_report and results:
                    misp_data = self.handle_misp_reporting(request, results)

                # Handle output format (now with MISP data available)
                self.output.render(results, misp_data=misp_data)

        except KeyboardInterrupt:
            if not args.robot:
                print("\nScan interrupted by user")
            sys.exit(1)
        except Exception as e:
            error_msg = f"Error: {e}"
            if args.robot:
                # Log error in robot mode
                if self.logger:
                    self.logger.log_error(args.target or "unknown", "system", error_msg)
            else:
                print(error_msg)
            if args.verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    def _handle_file_scanning(self, request: ScanRequest, results: List[Any]) -> None:
        """Handle file scanning functionality."""
        target = request.target
        if not request.robot:
            print("\nFILE SCANNING")
            print("=" * 50)

        # Extract download URLs from results (simplified logic)
        download_urls = self._extract_download_urls(target, results)

        if not download_urls:
            if request.verbose:
                print("[INFO] No download URLs detected for file scanning")
            return

        if not request.robot:
            print(f"[INFO] Detected {len(download_urls)} potential download link(s):")
            for i, url in enumerate(download_urls, 1):
                print(f"  {i}. {url}")

        if request.download:
            if not request.robot:
                print("[INFO] File download scanning would be implemented here")

            # Log what would be done
            if self.logger:
                self.logger.log_synthesis(
                    "file_scanning",
                    target,
                    {
                        "mode": "download_enabled",
                        "detected_urls": download_urls,
                        "status": "not_implemented",
                    },
                )

        if request.auto_scan_files:
            if not request.robot:
                print(
                    "[INFO] Auto file scanning would process these downloads automatically"
                )

            # Log what would be done
            if self.logger:
                self.logger.log_synthesis(
                    "auto_file_scanning",
                    target,
                    {
                        "mode": "auto_scan",
                        "detected_urls": download_urls,
                        "status": "not_implemented",
                    },
                )

    def _extract_download_urls(self, target: str, results: List[Any]) -> List[str]:
        """Extract potential download URLs from scan results."""
        download_urls = []

        # Check if target itself looks like a download
        if self._is_download_url(target):
            download_urls.append(target)

        # Extract from YARA results if available
        for result in results:
            if hasattr(result, "provider") and result.provider == "yara":
                if hasattr(result, "details") and result.details:
                    # Look for download-related data in YARA details
                    if "download_links" in result.details:
                        download_urls.extend(result.details["download_links"])
                    elif "matches" in result.details:
                        # Check YARA matches for download patterns
                        matches = result.details["matches"]
                        for match in matches:
                            if isinstance(match, dict) and "rule" in match:
                                rule_name = match.get("rule", "").lower()
                                if any(
                                    keyword in rule_name
                                    for keyword in ["download", "file", "executable"]
                                ):
                                    # This match might indicate a download
                                    if "strings" in match:
                                        for string_match in match["strings"]:
                                            potential_url = str(string_match)
                                            if self._is_download_url(potential_url):
                                                download_urls.append(potential_url)

        # Remove duplicates
        return list(set(download_urls))

    def _is_download_url(self, url: str) -> bool:
        """Check if URL looks like a download link."""
        download_extensions = [
            ".exe",
            ".msi",
            ".dmg",
            ".pkg",
            ".deb",
            ".rpm",
            ".zip",
            ".tar",
            ".gz",
            ".7z",
            ".rar",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".apk",
            ".jar",
            ".bin",
        ]

        url_lower = url.lower().split("?")[0]  # Remove query params
        return any(url_lower.endswith(ext) for ext in download_extensions)

    def handle_misp_reporting(self, request: ScanRequest, results: List[Any]) -> dict:
        """Handle MISP threat intelligence reporting."""
        target = request.target
        misp_data = {"event_id": None, "status": "not_attempted", "error": None}

        try:
            from url_checker_tools.integrations.misp_reporter import MISPReporter

            # Create MISP reporter
            reporter = MISPReporter(verbose=request.verbose)

            if not reporter.is_available():
                misp_data["status"] = "unavailable"
                misp_data["error"] = "MISP reporter not available - check configuration"
                if request.verbose:
                    print(f"[WARNING] {misp_data['error']}")
                return misp_data

            # Filter threat results for reporting
            threat_results = [
                r for r in results if hasattr(r, "is_threat") and r.is_threat
            ]

            if not threat_results:
                misp_data["status"] = "skipped_no_threats"
                if request.verbose:
                    print("[INFO] No threats detected - skipping MISP report")
                return misp_data

            # Create MISP event
            event_result = reporter.create_event(
                target=target, results=results, session_id=self.session_id
            )

            if event_result:
                misp_data["event_id"] = event_result["event_id"]
                misp_data["uuid"] = event_result["uuid"]
                misp_data["status"] = "success"
                if request.verbose:
                    print(
                        f"[INFO] MISP event created: Event ID {event_result['event_id']} (UUID: {event_result['uuid']})"
                    )
                else:
                    print(f"MISP event created: {event_result['event_id']}")
            else:
                misp_data["status"] = "failed"
                misp_data["error"] = "Failed to create MISP event"
                if request.verbose:
                    print(f"[ERROR] {misp_data['error']}")

        except ImportError:
            misp_data["status"] = "module_unavailable"
            misp_data["error"] = "MISP integration module not available"
            if request.verbose:
                print(f"[WARNING] {misp_data['error']}")
        except Exception as e:
            misp_data["status"] = "error"
            misp_data["error"] = str(e)
            if request.verbose:
                print(f"[ERROR] MISP reporting failed: {e}")
            else:
                print(f"MISP reporting error: {e}")

        return misp_data


# Standalone functions for backward compatibility with tests
def create_argument_parser():
    """Create and return the argument parser (for test compatibility)."""
    cli = URLCheckerCLI()
    return cli.create_argument_parser()


def main():
    """Run the command-line entry point."""
    cli = URLCheckerCLI()
    cli.main()


if __name__ == "__main__":
    main()
