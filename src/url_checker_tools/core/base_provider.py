#!/usr/bin/env python3
"""Base provider ABC class with all common functionality."""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from url_checker_tools.config import logging_config
from url_checker_tools.config.provider_config import ProviderConfigTemplate

from .http_client import HTTPClient
from .results import ProviderResult, ThreatLevel
from .utils import ConfigDict


class BaseProvider(ABC):
    """Base class that all providers inherit from. Contains everything a provider needs."""

    def __init__(self, provider_name: str, config: Optional[Dict] = None):
        self.provider_name = provider_name

        # Auto-load configuration if not provided
        raw_config = config or ProviderConfigTemplate.get_all_provider_configs().get(
            provider_name, {}
        )

        # Wrap dictionary config for attribute access
        if isinstance(raw_config, dict):
            self.config = ConfigDict(raw_config)
        else:
            self.config = raw_config

        # Set up logger
        self.logger = logging_config.get_logger()

        # Set up HTTP client
        self.http = HTTPClient(provider_name, self.config, self.logger)

        # Log configuration (sanitized)
        self._log_configuration()

    @abstractmethod
    def scan(self, target: str) -> ProviderResult:
        """Scan a target and return results. Must be implemented by each provider."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if provider is properly configured and available."""
        pass

    def scan_with_timing(self, target: str) -> ProviderResult:
        """Wrapper that adds timing and logging to scan method."""
        start_time = time.time()

        # Log scan start
        self.logger.log_provider_start(
            workflow_id=getattr(self, "_workflow_id", "unknown"),
            provider=self.provider_name,
            target=target,
        )

        try:
            # Check availability first
            if not self.is_available():
                return self._create_error_result(
                    target,
                    f"{self.provider_name} is not properly configured or unavailable",
                )

            # Perform the actual scan
            result = self.scan(target)

            # Set execution time
            result.execution_time = time.time() - start_time

            # Log result
            self._log_result(target, result)

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"{self.provider_name} scan failed: {str(e)}"

            # Log error
            self.logger.log_error(
                target,
                self.provider_name,
                error_msg,
                {"execution_time": execution_time, "exception_type": type(e).__name__},
            )

            return self._create_error_result(target, error_msg, execution_time)

    def _create_error_result(
        self, target: str, error_message: str, execution_time: Optional[float] = None
    ) -> ProviderResult:
        """Create a standardized error result."""
        return ProviderResult(
            provider=self.provider_name,
            target=target,
            is_threat=False,
            threat_level=ThreatLevel.ERROR,
            confidence=0.0,
            details={"error": error_message},
            timestamp=None,
            execution_time=execution_time,
            error_message=error_message,
        )

    def _create_safe_result(
        self, target: str, details: Dict[str, Any] = None, confidence: float = 0.9
    ) -> ProviderResult:
        """Create a standardized safe result."""
        return ProviderResult(
            provider=self.provider_name,
            target=target,
            is_threat=False,
            threat_level=ThreatLevel.SAFE,
            confidence=confidence,
            details=details or {},
            timestamp=None,
            execution_time=None,
            error_message=None,
        )

    def _create_threat_result(
        self,
        target: str,
        threat_level: ThreatLevel,
        details: Dict[str, Any] = None,
        confidence: float = 0.8,
    ) -> ProviderResult:
        """Create a standardized threat result."""
        return ProviderResult(
            provider=self.provider_name,
            target=target,
            is_threat=True,
            threat_level=threat_level,
            confidence=confidence,
            details=details or {},
            timestamp=None,
            execution_time=None,
            error_message=None,
        )

    def _log_configuration(self) -> None:
        """Log provider configuration without sensitive data."""
        safe_config = {
            "provider": self.provider_name,
            "timeout": self.config.timeout,
            "max_retries": self.config.max_retries,
            "rate_limit": self.config.rate_limit_per_minute,
            "verbose": self.config.verbose,
        }

        # Add provider-specific safe config items
        if hasattr(self.config, "endpoint"):
            safe_config["endpoint"] = self.config.endpoint

        self.logger.log_configuration(self.provider_name, safe_config)

    def _log_result(self, target: str, result: ProviderResult) -> None:
        """Log provider result summary."""
        result_summary = {
            "is_threat": result.is_threat,
            "threat_level": result.threat_level.value,
            "confidence": result.confidence,
            "execution_time": result.execution_time,
            "is_error": result.is_error,
            "details_size": len(str(result.details)) if result.details else 0,
        }

        self.logger.log_provider_result(
            workflow_id=getattr(self, "_workflow_id", "unknown"),
            provider=self.provider_name,
            target=target,
            result_summary=result_summary,
        )

    def set_workflow_id(self, workflow_id: str) -> None:
        """Set workflow ID for logging context."""
        self._workflow_id = workflow_id

    def close(self) -> None:
        """Clean up provider resources."""
        if hasattr(self, "http") and self.http:
            self.http.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
