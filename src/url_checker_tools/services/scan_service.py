"""Direct scan: runs the selected providers on a target and collects their results."""

from typing import Any, List, Optional

from url_checker_tools.config.logging_config import WorkflowLogger
from url_checker_tools.output.formatters import get_formatter
from url_checker_tools.services.file_scan_service import FileScanService
from url_checker_tools.services.provider_registry import ProviderRegistry
from url_checker_tools.services.scan_request import ScanRequest


class ScanService:
    """Runs a scan request against the registered providers."""

    def __init__(
        self,
        registry: ProviderRegistry,
        logger: Optional[WorkflowLogger],
        file_scans: FileScanService,
    ):
        self.registry = registry
        self.logger = logger
        self.file_scans = file_scans

    def run(self, request: ScanRequest, events) -> List[Any]:
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
            self.file_scans.handle(request, results)

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

            # Verbose robot mode: show human-readable summary
            if request.verbose:
                events.robot_verbose_summary(results, target)

        return results
