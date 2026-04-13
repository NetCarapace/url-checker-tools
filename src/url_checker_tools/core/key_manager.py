#!/usr/bin/env python3
"""Simplified API key management using system keyring."""

import os

import keyring
import keyring.errors

from url_checker_tools.core.exceptions import MissingAPIKeyError


class KeyManager:
    """Manages API keys using the system keyring."""

    def get_virustotal_key(self) -> str:
        """Get VirusTotal API key from keyring."""
        return self._get_key("virustotal", required=True)

    def get_urlscan_key(self) -> str:
        """Get URLScan.io API key from keyring."""
        return self._get_key("urlscan", required=True)

    def get_google_sb_key(self) -> str:
        """Get Google Safe Browsing API key from keyring."""
        return self._get_key("googlesafebrowsing", required=True)

    def get_abuseipdb_key(self) -> str:
        """Get AbuseIPDB API key from keyring."""
        return self._get_key("abuseipdb", required=True)

    def get_whalebone_key(self) -> str:
        """Get Whalebone API secret-key (actual api key) from keyring."""
        return self._get_key("whalebone_apisecretkey", required=True)

    def get_whalebone_user(self) -> str:
        """Get Whalebone API access-key (userID) from keyring."""
        return self._get_key("whalebone_apiaccesskey", required=True)

    def has_virustotal_key(self) -> bool:
        """Check if VirusTotal API key exists."""
        try:
            self._get_key("virustotal", required=True)
            return True
        except MissingAPIKeyError:
            return False

    def has_urlscan_key(self) -> bool:
        """Check if URLScan.io API key exists."""
        try:
            self._get_key("urlscan", required=True)
            return True
        except MissingAPIKeyError:
            return False

    def has_google_sb_key(self) -> bool:
        """Check if Google Safe Browsing API key exists."""
        try:
            self._get_key("googlesafebrowsing", required=True)
            return True
        except MissingAPIKeyError:
            return False

    def has_abuseipdb_key(self) -> bool:
        """Check if AbuseIPDB API key exists."""
        try:
            self._get_key("abuseipdb", required=True)
            return True
        except MissingAPIKeyError:
            return False

    def has_whalebone_key(self) -> bool:
        """Check if Whalebone API key exists."""
        try:
            self._get_key("whalebone_apisecretkey", required=True)
            return True
        except MissingAPIKeyError:
            return False

    def has_whalebone_user(self) -> bool:
        """Check if Whalebone API key exists."""
        try:
            self._get_key("whalebone_apiaccesskey", required=True)
            return True
        except MissingAPIKeyError:
            return False

    def store_key(self, account: str, api_key: str) -> None:
        """Store an API key in the keyring."""
        if not api_key or not api_key.strip():
            raise ValueError("API key cannot be empty")

        keyring.set_password("urlchecker", account, api_key.strip())
        # Add to registry so it shows up in list
        self._update_accounts_registry(account)

    def delete_key(self, account: str) -> None:
        """Delete an API key from the keyring."""
        try:
            keyring.delete_password("urlchecker", account)
            # Remove from registry
            self._remove_from_registry(account)
        except keyring.errors.PasswordDeleteError:
            # Key doesn't exist, which is fine
            # Still try to remove from registry in case it's orphaned
            self._remove_from_registry(account)

    def list_stored_accounts(self) -> list:
        """List accounts that have stored keys."""
        # Get the registry of stored accounts
        registry = self._get_accounts_registry()
        accounts = []

        # Verify each registered account still has a key
        for account in registry:
            try:
                self._get_key(account, required=True)
                accounts.append(account)
            except MissingAPIKeyError:
                # Account was in registry but key no longer exists, remove it
                self._remove_from_registry(account)

        return accounts

    def _get_accounts_registry(self) -> list:
        """Get list of accounts that have been registered."""
        registry_key = "___accounts_registry___"
        registry_data = keyring.get_password("urlchecker", registry_key)

        if registry_data:
            try:
                # Split by newlines to get list of accounts
                return [acc.strip() for acc in registry_data.split("\n") if acc.strip()]
            except Exception:
                return []
        return []

    def _update_accounts_registry(self, account: str) -> None:
        """Add an account to the registry."""
        registry = self._get_accounts_registry()
        if account not in registry:
            registry.append(account)
            registry_key = "___accounts_registry___"
            keyring.set_password("urlchecker", registry_key, "\n".join(registry))

    def _remove_from_registry(self, account: str) -> None:
        """Remove an account from the registry."""
        registry = self._get_accounts_registry()
        if account in registry:
            registry.remove(account)
            registry_key = "___accounts_registry___"
            if registry:
                keyring.set_password("urlchecker", registry_key, "\n".join(registry))
            else:
                # If no accounts left, delete the registry
                try:
                    keyring.delete_password("urlchecker", registry_key)
                except keyring.errors.PasswordDeleteError:
                    pass

    def _get_key(self, account: str, required: bool = True) -> str:
        """Get an API key from the keyring."""
        env_var_name = f"URLCHECKERTOOLS_{account.upper()}"
        if os.environ.get(env_var_name):
            # Environment variable is set, skip keyring
            key = os.environ.get(env_var_name)
        else:
            key = keyring.get_password("urlchecker", account)

        if key and key.strip():
            return key.strip()

        if required:
            raise MissingAPIKeyError(
                f"No API key found for {account}. "
                f"Use the key management tool to add it: "
                f"python tools/manage_keys.py add --account {account}"
            )

        return ""
