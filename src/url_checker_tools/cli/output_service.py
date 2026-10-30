"""CLI output: result rendering, robot summaries and provider listings."""

import json
from typing import Any, Callable, Dict, List, Optional

from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer
from url_checker_tools.config.logging_config import WorkflowLogger
from url_checker_tools.core.results import ProviderResult
from url_checker_tools.output.formatters import get_formatter
from url_checker_tools.services.provider_details import unique_categories
from url_checker_tools.services.provider_registry import ProviderRegistry
from url_checker_tools.services.scan_request import ScanRequest

# Provider-specific detail appended to the robot verbose summary status


def _describe_virustotal(status: str, details: Dict[str, Any]) -> str:
    malicious_count = details.get("malicious_count", 0)
    total_count = details.get("total_engines", 0)
    if malicious_count > 0:
        status = f"malicious ({malicious_count}/{total_count} vendors)"
    elif total_count > 0:
        status = f"safe ({total_count - malicious_count} clean vendors)"
    # Append VT categories/tags if available
    unique_cats = unique_categories(details)
    if unique_cats:
        status = f"{status} (categories: {', '.join(unique_cats)})"
    return status


def _describe_whalebone(status: str, details: Dict[str, Any]) -> str:
    # Include threat types (deduped) and max accuracy, plus categories and classification
    threat_types = details.get("threat_types", []) or []
    max_acc = details.get("max_accuracy", details.get("accuracy", 0)) or 0
    categories = details.get("categories", []) or []
    cls = (
        details.get("category_classification", {}) if isinstance(details, dict) else {}
    )

    if threat_types:
        types_str = ", ".join(
            sorted(set([t for t in threat_types if isinstance(t, str)]))
        )
        status = f"{status} (threats: {types_str} (max {int(max_acc)}%))"

    if categories:
        category_str = ", ".join(
            sorted(set([c for c in categories if isinstance(c, str)]))
        )
        status = f"{status} (categories: {category_str})"
    # Display classification groups compactly if available
    if isinstance(cls, dict) and any(
        cls.get(k) for k in ["security", "policy", "safe", "unknown"]
    ):
        parts = []
        for grp in ["security", "policy", "safe", "unknown"]:
            vals = cls.get(grp) or []
            if isinstance(vals, list) and vals:
                parts.append(
                    f"{grp}:{len(set([v for v in vals if isinstance(v, str)]))}"
                )
        if parts:
            status = f"{status} [classification: {'; '.join(parts)}]"
    return status


def _describe_misp(status: str, details: Dict[str, Any]) -> str:
    events_found = details.get("events_found", 0)
    if events_found > 0:
        status = f"{status} ({events_found} events found)"
    return status


VERBOSE_DETAILS: Dict[str, Callable[[str, Dict[str, Any]], str]] = {
    "virustotal": _describe_virustotal,
    "whalebone": _describe_whalebone,
    "misp": _describe_misp,
}


# Provider listing hints (--list-providers / --providers-status)

# Keyring accounts KeyManager reads (env var: URLCHECKERTOOLS_<ACCOUNT>)
API_KEY_ACCOUNTS = {
    "virustotal": ["virustotal_apikey"],
    "whalebone": ["whalebone_apisecretkey", "whalebone_apiaccesskey"],
    "urlscan": ["urlscan_apikey"],
    "google_sb": ["googlesafebrowsing_apikey"],
    "abuseipdb": ["abuseipdb_apikey"],
}
API_KEY_PROVIDERS = list(API_KEY_ACCOUNTS)

AVAILABLE_HINTS = {
    **{name: " (API key configured)" for name in API_KEY_PROVIDERS + ["misp"]},
    "lookyloo": " (no API key required)",
    "whois": " (built-in functionality)",
}

UNAVAILABLE_HINTS = {
    **{name: " (missing API key)" for name in API_KEY_PROVIDERS},
    "yara": " (no YARA rules found)",
    "misp": " (missing MISP configuration)",
}


def _yara_rules_hint(config) -> str:
    if hasattr(config, "rule_paths") and config.rule_paths:
        return f" (custom rules: {len(config.rule_paths)})"
    if hasattr(config, "rules_dir"):
        return f" (rules dir: {config.rules_dir})"
    return ""


def _status_yara(name: str, config) -> None:
    if hasattr(config, "rule_paths") and config.rule_paths:
        print(f"  Custom rules: {len(config.rule_paths)} paths")
        for i, path in enumerate(config.rule_paths[:3], 1):
            print(f"    {i}. {path}")
        if len(config.rule_paths) > 3:
            print(f"    ... and {len(config.rule_paths) - 3} more")
    else:
        print(f"  Rules directory: {config.rules_dir}")
    print(f"  Max file size: {config.max_file_size / (1024*1024):.1f} MB")
    print(f"  Scan timeout: {config.scan_timeout}s")


def _status_whalebone(name: str, config) -> None:
    if hasattr(config, "endpoint"):
        print(f"  Endpoint: {config.endpoint}")
    if hasattr(config, "min_threat_accuracy"):
        print(f"  Min threat accuracy: {config.min_threat_accuracy}%")


def _status_whois(name: str, config) -> None:
    print("  Built-in WHOIS client")


def _status_lookyloo(name: str, config) -> None:
    print("  Public service (no API key required)")
    if hasattr(config, "endpoint"):
        print(f"  Endpoint: {config.endpoint}")


def _status_api_key(name: str, config) -> None:
    print("  API key: configured")
    if hasattr(config, "endpoint"):
        print(f"  Endpoint: {config.endpoint}")
    if hasattr(config, "rate_limit_per_minute"):
        print(f"  Rate limit: {config.rate_limit_per_minute}/min")


STATUS_DETAILS: Dict[str, Callable[[str, Any], None]] = {
    "yara": _status_yara,
    "whalebone": _status_whalebone,
    "whois": _status_whois,
    "lookyloo": _status_lookyloo,
    **{
        name: _status_api_key
        for name in ["virustotal", "urlscan", "google_sb", "abuseipdb", "misp"]
    },
}


def _help_missing_api_key(name: str, config) -> None:
    print("  Issue: Missing API key")
    print("  Solution: Set API key via keyring or environment variable")
    for account in API_KEY_ACCOUNTS[name]:
        print(f"    - Keyring: python tools/manage_keys.py add --account {account}")
        print(f"    - Env var: URLCHECKERTOOLS_{account.upper()}=<your-api-key>")


def _help_yara(name: str, config) -> None:
    print("  Issue: No YARA rules found")
    print("  Solution: Add .yar files to 'rules/' directory or use --yara-rules")
    if hasattr(config, "rules_dir"):
        print(f"  Current rules directory: {config.rules_dir}")


def _help_misp(name: str, config) -> None:
    print("  Issue: MISP configuration missing")
    print("  Solution: Configure MISP server URL and API key")


TROUBLESHOOTING: Dict[str, Callable[[str, Any], None]] = {
    **{name: _help_missing_api_key for name in API_KEY_PROVIDERS},
    "yara": _help_yara,
    "misp": _help_misp,
}


class OutputService:
    """Renders scan results and provider information for the command line."""

    def __init__(
        self,
        request: ScanRequest,
        logger: Optional[WorkflowLogger],
        write_robot_logs: Callable,
        registry: ProviderRegistry,
    ):
        self.request = request
        self.logger = logger
        self.write_robot_logs = write_robot_logs
        self.registry = registry
        self.output_format = "json" if request.raw else request.format
        self.formatter = get_formatter(self.output_format)

    def render(self, results: List[Any], misp_data: dict = None) -> None:
        """Handle different output formats."""
        request = self.request
        output_str = None
        scoring_data = None

        # Calculate scoring data if requested (for inclusion in logs)
        if (request.score or request.score_detail) and results:
            from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer

            scorer = UnifiedThreatScorer()
            scoring_data = scorer.calculate_threat_score(results)

        if request.format == "json" or request.raw or request.robot:
            # JSON output (default for robot mode)
            json_output = {
                "session_id": request.session_id,
                "results": [
                    r.to_dict() if hasattr(r, "to_dict") else str(r) for r in results
                ],
            }

            # Add scoring data if available
            if scoring_data:
                json_output["scoring"] = scoring_data

            output_str = json.dumps(json_output, indent=2)
            if not request.robot:
                print(output_str)

            # Create dual logs for robot mode
            if request.robot and self.logger:
                self._write_robot_logs(request.target, results, output_str, misp_data)

        elif request.format == "synthesis":
            # Synthesis output - only calculate scoring if --score or --score-detail flag is present
            if request.score or request.score_detail:
                # Use pre-calculated scoring data
                if not scoring_data:
                    from url_checker_tools.analysis.unified_scorer import (
                        UnifiedThreatScorer,
                    )

                    scorer = UnifiedThreatScorer()
                    scoring_data = scorer.calculate_threat_score(results)

                score = scoring_data["final_score"]
                verdict = scoring_data["verdict"]
                threat_level_map = scorer.get_threat_level_mapping()

                synthesis = {
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
            else:
                # Simple synthesis without detailed scoring when --score not requested
                threat_count = sum(
                    1 for r in results if hasattr(r, "is_threat") and r.is_threat
                )
                valid_results = [
                    r for r in results if not getattr(r, "is_error", False)
                ]

                synthesis = {
                    "synthesis": {
                        "threat_level": "high" if threat_count > 0 else "safe",
                        "confidence": 0.8 if threat_count > 0 else 0.9,
                        "providers_checked": len(valid_results),
                        "threats_detected": threat_count,
                    }
                }
            output_str = json.dumps(synthesis, indent=2)
            if not request.robot:
                print(output_str)

            # Create dual logs for robot mode
            if request.robot and self.logger:
                self._write_robot_logs(request.target, results, output_str, misp_data)

        elif request.format == "human":
            # Human-readable output - capture for logging if needed
            formatter = get_formatter("human")
            human_lines = []
            for result in results:
                if hasattr(result, "provider"):
                    formatted_result = formatter.format_provider_result(result)
                    print(formatted_result)
                    human_lines.append(formatted_result)

            # If logging enabled, format human output for log file
            if request.log and self.logger and not request.robot:
                output_str = "\n".join(human_lines)

        # Create single log file for --log mode (not robot mode)
        if request.log and self.logger and not request.robot and output_str:
            try:
                # Pass scoring data to the logger if available
                log_path = self.logger.create_session_log(
                    request.target,
                    output_str,
                    request.format,
                    scoring_data=scoring_data,
                )
                print(f"[INFO] Log saved to: {log_path}")
            except Exception as e:
                print(f"[ERROR] Failed to create log file: {e}")

    def _write_robot_logs(
        self, target: str, results: List[Any], synthesis_json: str, misp_data: dict
    ) -> None:
        """Write the robot logs and print where they are (or why they failed)."""
        try:
            synthesis_path, detailed_path = self.write_robot_logs(
                target, results, synthesis_json, misp_data
            )
            print("[INFO] Robot logs created:")
            print(f"  Synthesis: {synthesis_path}")
            print(f"  Detailed: {detailed_path}")
        except Exception as e:
            print(f"[ERROR] Failed to create robot logs: {e}")

    def robot_verbose_summary(self, results: List[Any], target: str) -> None:
        """Show detailed human-readable summary for robot verbose mode."""
        print("\n" + "=" * 60)
        print("HUMAN-READABLE SUMMARY")
        print("=" * 60)

        # Show provider results with icons
        for result in results:
            if not hasattr(result, "provider"):
                continue

            provider_name = result.provider
            is_threat = getattr(result, "is_threat", False)
            is_error = getattr(result, "is_error", False)

            # Status icon
            if is_error:
                status_icon = "x"
                status = "unavailable" if result.is_unavailable else "error"
            elif is_threat:
                status_icon = "⚠"
                status = "threat detected"
            else:
                status_icon = "✓"
                status = "safe"

            # Enhanced status display for specific providers
            describe = VERBOSE_DETAILS.get(provider_name)
            if describe and hasattr(result, "details") and result.details:
                status = describe(status, result.details)

            print(f"{status_icon} {provider_name}: {status}")

            # Show threat details if available
            if is_threat and hasattr(result, "threat_level"):
                threat_level = getattr(result, "threat_level", None)
                if threat_level and hasattr(threat_level, "value"):
                    print(f"   └─ Threat Level: {threat_level.value}")

    def misp_reported(self, misp_data: dict) -> None:
        """Print the outcome of MISP reporting."""
        status = misp_data["status"]
        error = misp_data["error"]
        verbose = self.request.verbose

        if status in ("unavailable", "module_unavailable"):
            if verbose:
                print(f"[WARNING] {error}")
        elif status == "skipped_no_threats":
            if verbose:
                print("[INFO] No threats detected - skipping MISP report")
        elif status == "success":
            if verbose:
                print(
                    f"[INFO] MISP event created: Event ID {misp_data['event_id']} (UUID: {misp_data['uuid']})"
                )
            else:
                print(f"MISP event created: {misp_data['event_id']}")
        elif status == "failed":
            if verbose:
                print(f"[ERROR] {error}")
        elif status == "error":
            if verbose:
                print(f"[ERROR] MISP reporting failed: {error}")
            else:
                print(f"MISP reporting error: {error}")

    # ---- Scan progress (ScanEvents) ---------------------------------------

    def scan_started(self, request: ScanRequest) -> None:
        """Print the scan header."""
        providers = request.providers
        target = request.target

        # Robot mode output handling
        if request.robot:
            # Always show SID first in robot mode
            print(f"SID: {request.session_id}")

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

    def provider_unknown(self, name: str) -> None:
        if not self.request.robot:
            print(f"Unknown provider: {name}")

    def provider_started(self, name: str) -> None:
        if not self.request.robot:
            print(f"Running {name}...")
            if self.request.verbose:
                print(f"[INFO] Starting {name} scan...")

    def provider_scanning(self, name: str) -> None:
        # In robot mode, suppress individual provider verbose messages during scanning
        if self.request.verbose and not self.request.robot:
            print(f"[INFO] {name} provider is available, starting scan...")

    def provider_result(self, name: str, result: ProviderResult) -> None:
        request = self.request
        # Verbose execution details (suppress in robot mode during scanning)
        if request.verbose and not request.robot:
            exec_time = getattr(result, "execution_time", 0) or 0
            print(
                f"[INFO] {name} completed in {exec_time:.2f}s - {'Threat' if result.is_threat else 'Safe'}"
            )

        # Display result (unless in robot mode)
        if not request.robot:
            print(self.formatter.format_provider_result(result))

    def provider_unavailable(self, name: str) -> None:
        if not self.request.robot:
            print(f"  {name} is not properly configured")
        # In robot mode, suppress availability warnings during scanning
        if self.request.verbose and not self.request.robot:
            print(f"[WARNING] {name} provider availability check failed")

    def provider_failed(self, name: str, error: Exception) -> None:
        if not self.request.robot:
            print(f"   {name} scan failed: {error}")
        if self.request.verbose:
            print(f"[ERROR] {name} exception details: {str(error)[:200]}")

    def download_links_checked(
        self, request: ScanRequest, download_urls: List[str]
    ) -> None:
        """Print the file scanning section."""
        if not request.robot:
            print("\nFILE SCANNING")
            print("=" * 50)

        if not download_urls:
            if request.verbose:
                print("[INFO] No download URLs detected for file scanning")
            return

        if not request.robot:
            print(f"[INFO] Detected {len(download_urls)} potential download link(s):")
            for i, url in enumerate(download_urls, 1):
                print(f"  {i}. {url}")

        if request.download and not request.robot:
            print("[INFO] File download scanning would be implemented here")

        if request.auto_scan_files and not request.robot:
            print(
                "[INFO] Auto file scanning would process these downloads automatically"
            )

    def scan_finished(
        self, results: List[ProviderResult], scoring: Dict[str, Any]
    ) -> None:
        """Print the summary (and score) or, in robot mode, the RESULT line."""
        request = self.request

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
                scorer = UnifiedThreatScorer()

                # --score-detail supersedes --score
                if request.score_detail:
                    print(f"\n{scorer.format_scoring_details(scoring)}")
                else:
                    # Basic score output - use appropriate format
                    score_format = "json" if self.output_format == "json" else "human"
                    print(f"\n{scorer.format_basic_score(scoring, score_format)}")

            if request.verbose:
                print("[INFO] Provider results breakdown:")
                print(f"  - Safe: {safe_count}")
                print(f"  - Threats: {threat_count}")
                print(f"  - Errors: {error_count}")

        # Robot mode: Add RESULT output and optional verbose summary
        # Robot mode automatically behaves like --format synthesis --score (basic scoring, not detailed)
        if request.robot:
            print(f"RESULT: {scoring['verdict']} ({scoring['final_score']}/100)")

            # Verbose robot mode: show human-readable summary
            if request.verbose:
                self.robot_verbose_summary(results, request.target)

    @staticmethod
    def list_providers(registry: ProviderRegistry) -> None:
        """List all available providers with enhanced information."""
        print("Available providers:")
        print("=" * 50)

        available_count = 0
        total_count = len(registry.providers)

        for name, provider_class in registry.providers.items():
            try:
                with provider_class() as provider:
                    if provider.is_available():
                        status = "[AVAILABLE]"
                        available_count += 1

                        # Show provider-specific info
                        if name == "yara":
                            status += _yara_rules_hint(provider.config)
                        else:
                            status += AVAILABLE_HINTS.get(name, "")

                    else:
                        status = " Not configured"

                        # Provide helpful configuration hints
                        status += UNAVAILABLE_HINTS.get(name, "")

            except Exception as e:
                status = f" Error: {str(e)[:50]}"

            print(f"  {name:12} - {status}")

        print(f"\nSummary: {available_count}/{total_count} providers available")

        if available_count < total_count:
            print("\nConfiguration tips:")
            print("  - API keys can be set via keyring or environment variables")
            print(
                "  - Use 'python tools/manage_keys.py add --account <account>' for secure storage"
                " (account names: see --providers-status)"
            )
            print(
                "  - YARA provider needs rules in 'rules/' directory or use --yara-rules flag"
            )

    @staticmethod
    def provider_status(registry: ProviderRegistry) -> None:
        """Show detailed provider status with comprehensive information."""
        print("Provider Status Report:")
        print("=" * 60)

        available_providers = []
        unavailable_providers = []
        error_providers = []

        for name, provider_class in registry.providers.items():
            print(f"\n{name.upper()}:")
            try:
                # Use default configuration for status check
                provider = provider_class()
                with provider:
                    if provider.is_available():
                        print("  Status: [AVAILABLE]")
                        print(f"  Config: {provider.config.__class__.__name__}")

                        # Common configuration details
                        if hasattr(provider.config, "timeout"):
                            print(f"  Timeout: {provider.config.timeout}s")
                        if hasattr(provider.config, "max_retries"):
                            print(f"  Max retries: {provider.config.max_retries}")

                        # Provider-specific details
                        show_details = STATUS_DETAILS.get(name)
                        if show_details:
                            show_details(name, provider.config)

                        available_providers.append(name)

                    else:
                        print("  Status:  Not properly configured")

                        # Detailed troubleshooting information
                        show_help = TROUBLESHOOTING.get(name)
                        if show_help:
                            show_help(name, provider.config)

                        unavailable_providers.append(name)

            except Exception as e:
                print("  Status:  Error")
                print(f"  Error: {str(e)}")
                print(
                    "  Troubleshooting: Check provider implementation and dependencies"
                )
                error_providers.append(name)

        # Summary
        print(f"\n{'=' * 60}")
        print("SUMMARY:")
        print(f"  Available: {len(available_providers)} providers")
        if available_providers:
            print(f"    - {', '.join(available_providers)}")

        print(f"  Unavailable: {len(unavailable_providers)} providers")
        if unavailable_providers:
            print(f"    - {', '.join(unavailable_providers)}")

        print(f"  Errors: {len(error_providers)} providers")
        if error_providers:
            print(f"    - {', '.join(error_providers)}")

        print(
            f"\nOverall: {len(available_providers)}/{len(registry.providers)} providers ready"
        )

        if unavailable_providers or error_providers:
            print("\nNext steps:")
            print(
                "  1. Configure missing API keys for maximum threat detection coverage"
            )
            print("  2. Check provider documentation for setup requirements")
            print(
                f"  3. Test with available providers using: --providers {','.join(available_providers) if available_providers else 'none'}"
            )
