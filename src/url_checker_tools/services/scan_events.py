"""Events a scan reports while it runs, so callers decide how to show progress."""

from typing import Any, Dict, List, Protocol

from url_checker_tools.core.results import ProviderResult
from url_checker_tools.services.scan_request import ScanRequest


class ScanEvents(Protocol):
    """Receives scan progress from ScanService.run, in the order things happen."""

    def scan_started(self, request: ScanRequest) -> None:
        """The scan is about to run the selected providers."""

    def provider_unknown(self, name: str) -> None:
        """The provider name is not in the registry; it is skipped."""

    def provider_started(self, name: str) -> None:
        """The provider is about to be created."""

    def provider_scanning(self, name: str) -> None:
        """The provider is available and its scan starts."""

    def provider_result(self, name: str, result: ProviderResult) -> None:
        """The provider returned a result."""

    def provider_unavailable(self, name: str) -> None:
        """The provider is not configured, so it did not run."""

    def provider_failed(self, name: str, error: Exception) -> None:
        """The provider raised an exception."""

    def download_links_checked(
        self, request: ScanRequest, download_urls: List[str]
    ) -> None:
        """File scanning looked for download links (only with --download/--auto-scan-files)."""

    def scan_finished(
        self, results: List[ProviderResult], scoring: Dict[str, Any]
    ) -> None:
        """All providers ran; scoring is the unified threat score of the results."""
