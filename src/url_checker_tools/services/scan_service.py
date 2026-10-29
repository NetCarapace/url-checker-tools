"""Direct scan: runs the selected providers on a target and collects their results."""

from typing import List, Optional

from url_checker_tools.analysis.unified_scorer import UnifiedThreatScorer
from url_checker_tools.config.logging_config import WorkflowLogger
from url_checker_tools.core.results import ProviderResult, ThreatLevel
from url_checker_tools.services.file_scan_service import FileScanService
from url_checker_tools.services.provider_registry import ProviderRegistry
from url_checker_tools.services.scan_events import ScanEvents
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

    def run(self, request: ScanRequest, events: ScanEvents) -> List[ProviderResult]:
        """Perform direct scanning with specified providers, reporting progress to events."""
        target = request.target
        results = []

        events.scan_started(request)

        # Scan with each provider
        for provider_name in request.providers:
            provider_class = self.registry.get(provider_name)
            if not provider_class:
                events.provider_unknown(provider_name)
                continue

            events.provider_started(provider_name)

            try:
                # Initialize provider (configuration auto-loaded from enum)
                provider = provider_class()

                # Set verbose flag for base config if possible
                if hasattr(provider.config, "verbose"):
                    provider.config.verbose = request.verbose

                with provider:
                    if provider.is_available():
                        events.provider_scanning(provider_name)

                        result = provider.scan_with_timing(target)
                        results.append(result)

                        # Log to file if logging enabled
                        if self.logger:
                            self.logger.log_provider_result(result)

                        events.provider_result(provider_name, result)
                    else:
                        events.provider_unavailable(provider_name)
                        # In robot mode, record an error result so summaries include all enabled providers
                        if request.robot:
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
                events.provider_failed(provider_name, e)
                if self.logger:
                    self.logger.log_error(target, provider_name, error_msg)
                # In robot mode, append an error result so it's reflected in summaries and scoring
                if request.robot:
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

        scoring = UnifiedThreatScorer().calculate_threat_score(results)

        # Log scoring details if logging is enabled and scoring was requested
        if (
            not request.robot
            and (request.score or request.score_detail)
            and results
            and self.logger
        ):
            self.logger.log_synthesis(
                "manual_scoring",
                target,
                {
                    "scoring_system": "simplified_threat_scorer",
                    "scoring_data": scoring,
                },
            )

        events.scan_finished(results, scoring)
        return results
