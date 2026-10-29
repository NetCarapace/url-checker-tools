#!/usr/bin/env python3
"""A base config class for other providers"""

from pathlib import Path
from typing import Any, Dict

from .providers_enum import (
    ProviderDefaults,
    ProviderEndpoints,
    ProviderRateLimits,
    ProviderType,
    WhaleboneContentCategory,
)


class ProviderConfigTemplate:
    # TODO move this where it belongs !
    """Template for provider configurations using enumerations."""

    @staticmethod
    def get_whalebone_config() -> Dict[str, Any]:
        """Get Whalebone provider configuration."""
        return {
            "enabled": True,
            "endpoint": ProviderEndpoints.WHALEBONE.value,
            "api_key": None,  # Auto-loaded from keyring/env
            "user_id": None,  # Auto-loaded from keyring/env
            "min_threat_accuracy": 50,
            # Default category lists ported from old config
            "security_blacklisted_categories": [
                WhaleboneContentCategory.COINMINER.value,
                WhaleboneContentCategory.TERRORISM.value,
                WhaleboneContentCategory.CHILD_ABUSE.value,
                WhaleboneContentCategory.WEAPONS.value,
                WhaleboneContentCategory.DRUGS.value,
                WhaleboneContentCategory.RACISM.value,
                WhaleboneContentCategory.VIOLENCE.value,
                WhaleboneContentCategory.FAKENEWS.value,
            ],
            "policy_blacklisted_categories": [
                WhaleboneContentCategory.PORN.value,
                WhaleboneContentCategory.GAMBLING.value,
                WhaleboneContentCategory.P2P.value,
                WhaleboneContentCategory.DOH.value,
                WhaleboneContentCategory.TRACKING.value,
                WhaleboneContentCategory.ADVERTISEMENT.value,
            ],
            "whitelisted_categories": [
                WhaleboneContentCategory.AUDIO_VIDEO.value,
                WhaleboneContentCategory.SOCIAL_NETWORKS.value,
                WhaleboneContentCategory.GAMES.value,
                WhaleboneContentCategory.CHAT.value,
            ],
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
            "rate_limit_per_minute": ProviderRateLimits.WHALEBONE.value,
        }

    @staticmethod
    def get_virustotal_config() -> Dict[str, Any]:
        """Get VirusTotal provider configuration."""
        return {
            "enabled": True,
            "endpoint": ProviderEndpoints.VIRUSTOTAL.value,
            "api_key": None,  # Auto-loaded from keyring/env
            "rate_limit_per_minute": ProviderRateLimits.VIRUSTOTAL_FREE.value,
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
        }

    @staticmethod
    def get_google_sb_config() -> Dict[str, Any]:
        """Get Google Safe Browsing provider configuration."""
        return {
            "enabled": True,
            "endpoint": ProviderEndpoints.GOOGLE_SAFEBROWSING.value,
            "api_key": None,  # Auto-loaded from keyring/env
            "client_id": "url-checker-tools",
            "client_version": "1.0.0",
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
            "rate_limit_per_minute": ProviderRateLimits.GOOGLE_SAFEBROWSING.value,
        }

    @staticmethod
    def get_urlscan_config() -> Dict[str, Any]:
        """Get URLScan.io provider configuration."""
        return {
            "enabled": True,
            "endpoint": ProviderEndpoints.URLSCAN.value,
            "api_key": None,  # Auto-loaded from keyring/env
            "visibility": "public",
            "rate_limit_per_minute": ProviderRateLimits.URLSCAN.value,
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
        }

    @staticmethod
    def get_abuseipdb_config() -> Dict[str, Any]:
        """Get AbuseIPDB provider configuration."""
        return {
            "enabled": True,
            "endpoint": ProviderEndpoints.ABUSEIPDB.value,
            "api_key": None,  # Auto-loaded from keyring/env
            "confidence_threshold": 75,
            "max_age_days": 90,
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
            "rate_limit_per_minute": ProviderRateLimits.ABUSEIPDB.value,
        }

    @staticmethod
    def get_misp_config() -> Dict[str, Any]:
        """Get MISP provider configuration."""
        return {
            "enabled": True,
            "url": ProviderEndpoints.MISP.value,
            "api_key": None,  # Auto-loaded from keyring/env
            "verify_ssl": True,  # URLCHECKERTOOLS_MISP_VERIFYSSL=false for a self-signed local MISP
            "timeout": 60,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
            "rate_limit_per_minute": ProviderDefaults.RATE_LIMIT.value,
        }

    @staticmethod
    def get_lookyloo_config() -> Dict[str, Any]:
        """Get LookyLoo provider configuration."""
        return {
            "enabled": True,
            "endpoint": ProviderEndpoints.LOOKYLOO.value,
            "timeout": 60,  # Longer timeout for captures
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
            "rate_limit_per_minute": ProviderRateLimits.LOOKYLOO.value,
        }

    @staticmethod
    def get_link_analyzer_config() -> Dict[str, Any]:
        """Get Link Analyzer provider configuration."""
        return {
            "enabled": True,
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
            "rate_limit_per_minute": ProviderDefaults.RATE_LIMIT.value,
        }

    @staticmethod
    def get_yara_config() -> Dict[str, Any]:
        """Get YARA provider configuration."""
        import os

        # Allow configurable YARA rules directory via environment variable
        config_file = Path(__file__).resolve()
        project_root = (
            config_file.parent.parent.parent.parent
        )  # Go up from url_checker/src/urlchecker/config/
        default_rules_dir = (
            project_root / "data/yara"
        )  # set default rules directory relative to project root url_checker/
        rules_dir = os.getenv("URLCHECKER_YARA_RULES_DIR", default_rules_dir)

        return {
            "enabled": True,
            "rules_dir": rules_dir,
            "max_file_size": 10485760,  # 10MB
            "scan_timeout": 30,
            "timeout": ProviderDefaults.TIMEOUT.value,
            "max_retries": ProviderDefaults.MAX_RETRIES.value,
        }

    @staticmethod
    def get_whois_config() -> Dict[str, Any]:
        """Get WHOIS provider configuration."""
        return {
            "enabled": True,
            "timeout": 10,  # Shorter timeout for WHOIS
            "max_retries": 2,
        }

    @staticmethod
    def get_all_provider_configs() -> Dict[str, Dict[str, Any]]:
        """Get all provider configurations.

        This method now auto-populates API keys and related secrets from the system
        keyring using KeyManager, with environment variable fallbacks.
        """
        # Base configs
        configs = {
            ProviderType.WHALEBONE.value: ProviderConfigTemplate.get_whalebone_config(),
            ProviderType.VIRUSTOTAL.value: ProviderConfigTemplate.get_virustotal_config(),
            ProviderType.GOOGLE_SAFEBROWSING.value: ProviderConfigTemplate.get_google_sb_config(),
            ProviderType.URLSCAN.value: ProviderConfigTemplate.get_urlscan_config(),
            ProviderType.ABUSEIPDB.value: ProviderConfigTemplate.get_abuseipdb_config(),
            ProviderType.MISP.value: ProviderConfigTemplate.get_misp_config(),
            ProviderType.LOOKYLOO.value: ProviderConfigTemplate.get_lookyloo_config(),
            ProviderType.LINK_ANALYZER.value: ProviderConfigTemplate.get_link_analyzer_config(),
            ProviderType.YARA.value: ProviderConfigTemplate.get_yara_config(),
            ProviderType.WHOIS.value: ProviderConfigTemplate.get_whois_config(),
        }

        # Attempt to load secrets from keyring first, then env vars
        try:
            import os

            from url_checker_tools.core.exceptions import MissingAPIKeyError
            from url_checker_tools.core.key_manager import KeyManager

            # VirusTotal
            try:
                configs["virustotal"]["api_key"] = KeyManager().get_virustotal_key()
            except MissingAPIKeyError:
                configs["virustotal"]["api_key"] = (
                    os.getenv("VT_API_KEY")
                    or os.getenv("VIRUSTOTAL_API_KEY")
                    or configs["virustotal"].get("api_key")
                )

            # Google Safe Browsing
            try:
                configs["google_sb"]["api_key"] = KeyManager().get_google_sb_key()
            except MissingAPIKeyError:
                configs["google_sb"]["api_key"] = (
                    os.getenv("GOOGLE_SAFEBROWSING_API_KEY")
                    or os.getenv("GOOGLE_SB_API_KEY")
                    or configs["google_sb"].get("api_key")
                )

            # URLScan.io
            try:
                configs["urlscan"]["api_key"] = KeyManager().get_urlscan_key()
            except MissingAPIKeyError:
                configs["urlscan"]["api_key"] = os.getenv("URLSCAN_API_KEY") or configs[
                    "urlscan"
                ].get("api_key")

            # AbuseIPDB
            try:
                configs["abuseipdb"]["api_key"] = KeyManager().get_abuseipdb_key()
            except MissingAPIKeyError:
                configs["abuseipdb"]["api_key"] = os.getenv(
                    "ABUSEIPDB_API_KEY"
                ) or configs["abuseipdb"].get("api_key")

            # Whalebone (two-part credentials)
            try:
                configs["whalebone"]["api_key"] = KeyManager().get_whalebone_key()
            except MissingAPIKeyError:
                configs["whalebone"]["api_key"] = os.getenv(
                    "WHALEBONE_APISECRETKEY"
                ) or configs["whalebone"].get("api_key")
            try:
                configs["whalebone"]["user_id"] = KeyManager().get_whalebone_user()
            except MissingAPIKeyError:
                configs["whalebone"]["user_id"] = os.getenv(
                    "WHALEBONE_APIACCESSKEY"
                ) or configs["whalebone"].get("user_id")

            # MISP (URL + API key). KeyManager doesn’t define these; read env vars and try keyring accounts if present
            # Prefer environment variables if set
            misp_url_env = os.getenv("URLCHECKERTOOLS_MISP_URL") or os.getenv("MISP_URL")
            misp_key_env = (
                os.getenv("URLCHECKERTOOLS_MISP_APIKEY")
                or os.getenv("MISP_API_KEY")
                or os.getenv("MISP_KEY")
            )
            if misp_url_env:
                configs["misp"]["url"] = misp_url_env
            if os.getenv("URLCHECKERTOOLS_MISP_VERIFYSSL", "").lower() == "false":
                configs["misp"]["verify_ssl"] = False
            if misp_key_env:
                configs["misp"]["api_key"] = misp_key_env
            else:
                # Try common keyring accounts directly via keyring module
                try:
                    import keyring as _kr

                    k_url = _kr.get_password("urlchecker", "misp_url")
                    k_key = _kr.get_password("urlchecker", "misp") or _kr.get_password(
                        "urlchecker", "misp_api_key"
                    )
                    if k_url and not misp_url_env:
                        configs["misp"]["url"] = k_url.strip()
                    if k_key and not configs["misp"].get("api_key"):
                        configs["misp"]["api_key"] = k_key.strip()
                except Exception:
                    pass

            # Backwards-compat: some providers might expect different field names internally
            # Normalize common aliases
            if "misp" in configs:
                # Some MISP code paths use key/verifycert naming
                if configs["misp"].get("api_key") and not configs["misp"].get("key"):
                    configs["misp"]["key"] = configs["misp"]["api_key"]
                if "verify_ssl" in configs["misp"] and not configs["misp"].get(
                    "verifycert"
                ):
                    configs["misp"]["verifycert"] = configs["misp"]["verify_ssl"]

        except Exception:
            # Silently ignore secret loading errors so the rest of the config remains usable
            pass

        return configs
