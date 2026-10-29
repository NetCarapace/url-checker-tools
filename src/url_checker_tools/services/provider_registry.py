"""Provider registry: known providers, availability checks and provider selection."""

from typing import Dict, List, Optional, Type

from url_checker_tools.providers.abuseipdb import AbuseIPDBProvider
from url_checker_tools.providers.google_sb import GoogleSafeBrowsingProvider
from url_checker_tools.providers.link_analyzer import LinkAnalyzerProvider
from url_checker_tools.providers.lookyloo import LookyLooProvider
from url_checker_tools.providers.misp import MISPProvider
from url_checker_tools.providers.urlscan import URLScanProvider
from url_checker_tools.providers.virustotal import VirusTotalProvider
from url_checker_tools.providers.whalebone import WhaleboneProvider
from url_checker_tools.providers.whois import WhoisProvider
from url_checker_tools.providers.yara import YaraProvider

DEFAULT_PROVIDERS: Dict[str, Type] = {
    "whalebone": WhaleboneProvider,
    "virustotal": VirusTotalProvider,
    "whois": WhoisProvider,
    "google_sb": GoogleSafeBrowsingProvider,
    "abuseipdb": AbuseIPDBProvider,
    "urlscan": URLScanProvider,
    "lookyloo": LookyLooProvider,
    "link_analyzer": LinkAnalyzerProvider,
    "yara": YaraProvider,
    "misp": MISPProvider,
}


class ProviderRegistry:
    """Known provider classes, with a cached availability check and provider selection."""

    def __init__(self, providers: Optional[Dict[str, Type]] = None):
        self.providers = dict(providers or DEFAULT_PROVIDERS)
        self._available_cache: Optional[List[str]] = None

    def get(self, name: str) -> Optional[Type]:
        """Return the provider class registered under this name, or None."""
        return self.providers.get(name)

    def available(self, force_refresh: bool = False) -> List[str]:
        """Get list of providers that are actually available/configured.

        Uses caching to avoid repeated availability checks unless forced.
        """
        if self._available_cache is not None and not force_refresh:
            return self._available_cache.copy()

        available = []
        for name, provider_class in self.providers.items():
            try:
                with provider_class() as provider:
                    if provider.is_available():
                        available.append(name)
            except Exception:
                # Provider failed to initialize or check availability - skip it
                continue

        self._available_cache = available
        return available.copy()

    def select(
        self, providers_arg: Optional[str], use_all: bool, robot: bool
    ) -> List[str]:
        """Determine which providers to use from the --providers, --all and --robot options."""
        providers = []

        # Simple provider selection - flags accumulate, don't overwrite
        # 1. --providers explicit list
        # 2. --all-providers (all available)
        # 3. --all (reliable subset)
        # 4. Individual provider flags (accumulated)
        # 5. Default based on robot mode or all available

        # Get baseline providers (always included unless --all overrides everything)
        try:
            from url_checker_tools.config.robot_config import ProviderConfig

            baseline_providers = ProviderConfig.get_baseline_providers()
        except Exception:
            baseline_providers = ["whois", "link_analyzer"]

        if providers_arg:
            # Explicit provider list (comma-separated) + baseline providers
            additional_providers = [p.strip() for p in providers_arg.split(",")]
            providers = baseline_providers + additional_providers
        elif use_all:
            # All actually available/configured providers (overrides baseline)
            providers = self.available()
        elif robot:
            # Robot mode default providers (overrides baseline)
            try:
                from url_checker_tools.config.robot_config import RobotModeConfig

                providers = RobotModeConfig.get_robot_providers()
            except Exception:
                providers = [
                    "whois",
                    "link_analyzer",
                    "whalebone",
                    "virustotal",
                    "google_sb",
                    "yara",
                    "abuseipdb",
                ]
        else:
            # Default: only baseline providers
            providers = baseline_providers

        # Remove duplicates while preserving order
        seen = set()
        deduplicated_providers = []
        for provider in providers:
            if provider not in seen:
                seen.add(provider)
                deduplicated_providers.append(provider)

        return deduplicated_providers
