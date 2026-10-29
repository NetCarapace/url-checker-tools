"""File scanning of download links found during a scan (placeholder, not implemented yet)."""

from typing import Any, List, Optional

from url_checker_tools.config.logging_config import WorkflowLogger
from url_checker_tools.services.scan_request import ScanRequest


class FileScanService:
    """Detects download links in scan results and logs what file scanning would do."""

    def __init__(self, logger: Optional[WorkflowLogger]):
        self.logger = logger

    def handle(self, request: ScanRequest, results: List[Any]) -> List[str]:
        """Handle file scanning functionality; returns the detected download URLs."""
        target = request.target

        # Extract download URLs from results (simplified logic)
        download_urls = self._extract_download_urls(target, results)

        if not download_urls:
            return download_urls

        if request.download:
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

        return download_urls

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
