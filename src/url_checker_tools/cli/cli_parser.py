"""Command-line argument parser for url-checker."""

import argparse


class CLIParserFactory:
    """Builds the argparse parser with all CLI options."""

    @staticmethod
    def create() -> argparse.ArgumentParser:
        """Create comprehensive argument parser with all legacy options."""
        parser = argparse.ArgumentParser(
            description="Comprehensive URL and domain threat intelligence checker",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s example.com                          # Baseline scan (whois + link_analyzer)
  %(prog)s --providers virustotal,google_sb example.com  # Baseline + additional providers
  %(prog)s --all example.com                   # All available providers
  %(prog)s --list-providers                   # Show available providers

  # Robot mode for automation
  %(prog)s --robot --sid session123 example.com
  %(prog)s --robot --misp --sid session123 example.com        # Query MISP for existing events
  %(prog)s --robot --misp-report --sid session123 example.com # Create new MISP events
            """,
        )

        parser.add_argument("target", nargs="?", help="URL or domain to check")

        # Modern provider selection
        provider_group = parser.add_mutually_exclusive_group()
        provider_group.add_argument(
            "--providers",
            help="Comma-separated list of additional providers to run alongside baseline (whois,link_analyzer)",
        )
        provider_group.add_argument(
            "--all", action="store_true", help="Use all available providers"
        )

        # Output format options
        parser.add_argument(
            "--format",
            choices=["human", "json", "synthesis"],
            default="human",
            help="Output format",
        )
        parser.add_argument(
            "--raw",
            action="store_true",
            help="Output raw JSON (deprecated: use --format json)",
        )

        # YARA configuration
        parser.add_argument(
            "--yara-rules",
            nargs="*",
            default=[],
            help="Specific YARA rule files or directories to use",
        )
        parser.add_argument(
            "--yara-timeout",
            type=int,
            default=30,
            help="Timeout for fetching content (default: 30s)",
        )
        parser.add_argument(
            "--yara-max-bytes",
            type=int,
            default=10485760,  # 10MB
            help="Maximum bytes to scan (default: 10MB)",
        )

        # File scanning
        parser.add_argument(
            "--auto-scan-files",
            action="store_true",
            help="Automatically scan detected download files",
        )
        parser.add_argument(
            "--download",
            action="store_true",
            help="Enable file download scanning (placeholder)",
        )

        # Session and logging options
        parser.add_argument(
            "--sid",
            "--session-id",
            dest="session_id",
            help="Session ID for tracking and logging",
        )
        parser.add_argument(
            "--log",
            action="store_true",
            help="Save output to structured log file",
        )
        parser.add_argument(
            "--robot",
            action="store_true",
            help="Automation mode: minimal output, dual logging (.log/.dlog files). Requires --sid.",
        )
        parser.add_argument(
            "--score",
            action="store_true",
            help="Include basic threat score result",
        )
        parser.add_argument(
            "--score-detail",
            action="store_true",
            help="Include detailed scoring calculation breakdown (supersedes --score)",
        )

        # MISP reporting integration
        parser.add_argument(
            "--misp-report",
            action="store_true",
            help="Enable MISP threat intelligence reporting (create new MISP events from scan results)",
        )

        # Workflow options (new)
        parser.add_argument(
            "--workflow",
            choices=["fast", "complete", "reputation"],
            help="Use Celery workflow for distributed scanning",
        )

        # Provider information
        parser.add_argument(
            "--list-providers",
            action="store_true",
            help="List all available providers and exit",
        )
        parser.add_argument(
            "--providers-status",
            action="store_true",
            help="Show detailed provider status and exit",
        )

        # General options
        parser.add_argument(
            "--verbose", action="store_true", help="Enable verbose output"
        )

        return parser
