#!/usr/bin/env python3
"""Simplified tool for managing API keys."""

import argparse
import getpass
import sys
from pathlib import Path

# Ensure project src directory is on sys.path before importing urlchecker
try:
    _repo_root = Path(__file__).resolve().parents[1]
    _src_path = _repo_root / "src"
    if str(_src_path) not in sys.path:
        sys.path.insert(0, str(_src_path))
    if str(_repo_root) not in sys.path:
        sys.path.insert(0, str(_repo_root))
except Exception:
    pass

from url_checker_tools.config.display_constants import DisplayConstants
from url_checker_tools.core.exceptions import MissingAPIKeyError
from url_checker_tools.core.key_manager import KeyManager

# Service name used in keyring storage (must match KeyManager)
SERVICE_NAME = "urlchecker"


def create_argument_parser() -> argparse.ArgumentParser:
    """Create the argument parser for key management."""
    description = """Manage API keys for the URL checker.

Keys are stored in the system keyring using:
  Service: "urlchecker"
  Account: the account name the URL checker reads (below)

Accounts: virustotal_apikey, googlesafebrowsing_apikey, urlscan_apikey,
abuseipdb_apikey, whalebone_apisecretkey, whalebone_apiaccesskey,
misp (API key), misp_url

Examples:
  manage_keys add --account virustotal_apikey
  manage_keys add --account misp --key YOUR_API_KEY
  manage_keys list
  manage_keys delete --account virustotal_apikey
  manage_keys test --account googlesafebrowsing_apikey
  manage_keys test  # Test all stored keys
"""

    parser = argparse.ArgumentParser(
        prog="manage_keys",
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", metavar="COMMAND"
    )

    # Add key command
    add_parser = subparsers.add_parser(
        "add",
        help="Add an API key to the keyring",
        description="Store an API key securely in the system keyring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  manage_keys add --account virustotal_apikey
  manage_keys add --account misp --key abc123def456
  manage_keys add --account googlesafebrowsing_apikey""",
    )
    add_parser.add_argument(
        "--account",
        required=True,
        metavar="ACCOUNT",
        help="Account name (virustotal_apikey, googlesafebrowsing_apikey, misp, etc.)",
    )
    add_parser.add_argument(
        "--key",
        metavar="API_KEY",
        help="API key (will prompt securely if not provided)",
    )

    # List keys command
    subparsers.add_parser(
        "list",
        help="List all stored API keys",
        description="Display all API keys currently stored in the keyring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Shows which providers have API keys configured without revealing the keys",
    )

    # Delete key command
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete an API key from the keyring",
        description="Remove an API key from the system keyring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  manage_keys delete --account virustotal_apikey
  manage_keys delete --account misp""",
    )
    delete_parser.add_argument(
        "--account",
        required=True,
        metavar="ACCOUNT",
        help="Account name to delete API key for",
    )

    # Test keys command
    test_parser = subparsers.add_parser(
        "test",
        help="Test API key connectivity",
        description="Verify that API keys are accessible from the keyring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  manage_keys test                    # Test all stored keys
  manage_keys test --account virustotal_apikey  # Test specific account""",
    )
    test_parser.add_argument(
        "--account",
        metavar="ACCOUNT",
        help="Specific account to test (tests all if not specified)",
    )

    return parser


def add_key(key_manager: KeyManager, account: str, api_key: str = None) -> bool:
    """Add an API key to the keyring."""
    try:
        if not api_key:
            api_key = getpass.getpass(f"Enter API key for {account}: ")

        if not api_key.strip():
            print(DisplayConstants.format_error("API key cannot be empty"))
            return False

        key_manager.store_key(account, api_key)
        print(
            DisplayConstants.format_info(f"API key for {account} stored successfully")
        )
        return True

    except Exception as e:
        print(DisplayConstants.format_error(f"Failed to store API key: {e}"))
        return False


def list_keys(key_manager: KeyManager) -> bool:
    """List all stored API keys with complete keyring information."""
    try:
        print("Keyring Storage Information:")
        print(f"  Service Name: '{SERVICE_NAME}'")
        print(f"  Storage Format: service='{SERVICE_NAME}', account='<account_name>'")
        print()

        accounts = key_manager.list_stored_accounts()

        if not accounts:
            print("No API keys found in keyring")
            print()
            print("To add a key, use:")
            print("  manage_keys add --account <account_name>")
            print()
            print(
                "Accounts: virustotal_apikey, googlesafebrowsing_apikey, urlscan_apikey, misp"
            )
            return True

        print("Stored API Keys:")
        for account in accounts:
            # Get provider status information
            provider_info = _get_provider_info(account)
            status_icon = "✓"

            # Show keyring details
            print(f"  {status_icon} {account}")
            print(f"      Keyring: service='{SERVICE_NAME}', account='{account}'")
            if provider_info:
                print(f"      Provider: {provider_info}")
            print()

        print(f"Total: {len(accounts)} API key(s) stored")
        return True

    except Exception as e:
        print(DisplayConstants.format_error(f"Failed to list keys: {e}"))
        return False


def _get_provider_info(account: str) -> str:
    """Get descriptive information about a provider."""
    provider_descriptions = {
        "virustotal_apikey": "VirusTotal - Malware/URL analysis service",
        "googlesafebrowsing_apikey": "Google Safe Browsing - URL safety checking",
        "urlscan_apikey": "URLScan.io - Website screenshot and analysis",
        "abuseipdb_apikey": "AbuseIPDB - IP abuse reports",
        "whalebone_apisecretkey": "Whalebone - API secret key",
        "whalebone_apiaccesskey": "Whalebone - API access key",
        "misp": "MISP - Malware Information Sharing Platform (API key)",
        "misp_url": "MISP - server URL",
    }
    return provider_descriptions.get(account, f"Provider: {account}")


def delete_key(key_manager: KeyManager, account: str) -> bool:
    """Delete an API key from the keyring."""
    try:
        # Check if key exists
        try:
            key_manager._get_key(account, required=True)
        except MissingAPIKeyError:
            print(DisplayConstants.format_warning(f"No API key found for {account}"))
            return True

        # Confirm deletion
        response = input(f"Delete API key for {account}? (y/N): ")
        if response.lower() != "y":
            print("Deletion cancelled")
            return True

        key_manager.delete_key(account)
        print(
            DisplayConstants.format_info(f"API key for {account} deleted successfully")
        )
        return True

    except Exception as e:
        print(DisplayConstants.format_error(f"Failed to delete API key: {e}"))
        return False


def test_key(key_manager: KeyManager, account: str = None) -> bool:
    """Test API key connectivity."""
    if account:
        accounts_to_test = [account]
    else:
        # Test all stored accounts
        try:
            accounts_to_test = key_manager.list_stored_accounts()
            if not accounts_to_test:
                print("No API keys found to test")
                return True
        except Exception as e:
            print(DisplayConstants.format_error(f"Failed to list accounts: {e}"))
            return False

    all_success = True

    for test_account in accounts_to_test:
        try:
            print(f"Testing {test_account}...", end=" ")

            # Try to retrieve the key
            key_manager._get_key(test_account, required=True)

            # For a more thorough test, we could make an actual API call here
            # but for simplicity, we'll just check if the key exists
            print(
                DisplayConstants.format_with_color(
                    "✓ Key found", DisplayConstants.GREEN
                )
            )

        except Exception as e:
            print(DisplayConstants.format_with_color("✗ Failed", DisplayConstants.RED))
            print(f"  Error: {e}")
            all_success = False

    return all_success


def main() -> int:
    """Main entry point for the key management tool."""
    parser = create_argument_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    key_manager = KeyManager()

    try:
        if args.command == "add":
            success = add_key(key_manager, args.account, args.key)
        elif args.command == "list":
            success = list_keys(key_manager)
        elif args.command == "delete":
            success = delete_key(key_manager, args.account)
        elif args.command == "test":
            success = test_key(key_manager, getattr(args, "account", None))
        else:
            print(DisplayConstants.format_error(f"Unknown command: {args.command}"))
            return 1

        return 0 if success else 1

    except KeyboardInterrupt:
        print(DisplayConstants.format_info("Operation cancelled by user"))
        return 130
    except Exception as e:
        print(DisplayConstants.format_error(f"Unexpected error: {e}"))
        return 99


if __name__ == "__main__":
    sys.exit(main())
