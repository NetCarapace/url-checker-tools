#!/usr/bin/env python3
"""
Comprehensive URLChecker-Tools - Full-featured CLI wrapper to various cheker tools

Combines the new clean provider system with complete backward compatibility
for all original CLI options and functionality.
"""

import argparse
import sys
import uuid
from typing import Any, List, Optional

from url_checker_tools.cli.output_service import OutputService
from url_checker_tools.config.logging_config import WorkflowLogger, set_session_id
from url_checker_tools.services.file_scan_service import FileScanService
from url_checker_tools.services.provider_registry import ProviderRegistry
from url_checker_tools.services.robot_log_service import RobotLogBuilder
from url_checker_tools.services.scan_request import ScanRequest
from url_checker_tools.services.scan_service import ScanService
from url_checker_tools.workflows.orchestrator import WorkflowOrchestrator


class URLCheckerCLI:
    """Comprehensive CLI that integrates clean provider system with full functionality."""

    def __init__(self):
        """Initialize CLI with available providers."""
        self.registry = ProviderRegistry()

        self.logger: Optional[WorkflowLogger] = None
        self.session_id: Optional[str] = None

    def create_argument_parser(self) -> argparse.ArgumentParser:
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

    def setup_logging(self, args) -> None:
        """Set up logging based on CLI arguments."""
        if args.session_id:
            self.session_id = args.session_id
            set_session_id(args.session_id)
        else:
            self.session_id = str(uuid.uuid4())[:8]

        if args.log or args.robot:
            self.logger = WorkflowLogger(session_id=self.session_id)

    def _build_services(self, request: ScanRequest) -> ScanService:
        """Create the output and scan services for one request."""
        robot_logs = RobotLogBuilder(self.session_id, self.logger)
        self.output = OutputService(
            request, self.logger, robot_logs.write, self.registry
        )
        return ScanService(self.registry, self.logger, FileScanService(self.logger))

    def main(self) -> None:
        """Run the command-line interface."""
        parser = self.create_argument_parser()
        args = parser.parse_args()

        # Handle special cases first
        if args.list_providers:
            OutputService.list_providers(self.registry)
            return

        if args.providers_status:
            OutputService.provider_status(self.registry)
            return

        # Apply robot mode flags if robot mode is enabled
        if args.robot:
            try:
                from url_checker_tools.config.robot_config import RobotModeConfig

                RobotModeConfig.apply_robot_flags(args)
            except Exception as e:
                print(f"Warning: Failed to apply robot mode flags: {e}")

        # Validate robot mode requirements (after applying robot flags)
        if args.robot and not args.session_id:
            print("Error: --robot mode requires --sid/--session-id")
            sys.exit(1)

        # Require target for scanning
        if not args.target:
            print("Error: Target URL or domain is required")
            parser.print_help()
            sys.exit(1)

        # Setup logging
        self.setup_logging(args)

        # Build the request: everything below reads it instead of args
        providers = self.registry.select(args.providers, args.all, args.robot)
        request = ScanRequest.from_args(args, providers, self.session_id)
        scan_service = self._build_services(request)

        try:
            if request.workflow:
                # Use Celery workflow
                orchestrator = WorkflowOrchestrator(self.session_id)

                if request.workflow == "fast":
                    workflow_id = orchestrator.scan_url_fast(request.target)
                elif request.workflow == "reputation":
                    workflow_id = orchestrator.scan_domain_reputation(request.target)
                else:
                    workflow_id = orchestrator.scan_url_complete(request.target)

                if not request.robot:
                    print(f"Started workflow {workflow_id} for {request.target}")
                    print("Use 'celery flower' to monitor progress")
            else:
                # Direct scanning
                results = scan_service.run(request, self.output)

                # MISP reporting (if enabled) - do this before output format to capture event ID
                misp_data = None
                if request.misp_report and results:
                    misp_data = self.handle_misp_reporting(request, results)

                # Handle output format (now with MISP data available)
                self.output.render(results, misp_data=misp_data)

        except KeyboardInterrupt:
            if not request.robot:
                print("\nScan interrupted by user")
            sys.exit(1)
        except Exception as e:
            error_msg = f"Error: {e}"
            if request.robot:
                # Log error in robot mode
                if self.logger:
                    self.logger.log_error(
                        request.target or "unknown", "system", error_msg
                    )
            else:
                print(error_msg)
            if request.verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)

    def handle_misp_reporting(self, request: ScanRequest, results: List[Any]) -> dict:
        """Handle MISP threat intelligence reporting."""
        target = request.target
        misp_data = {"event_id": None, "status": "not_attempted", "error": None}

        try:
            from url_checker_tools.integrations.misp_reporter import MISPReporter

            # Create MISP reporter
            reporter = MISPReporter(verbose=request.verbose)

            if not reporter.is_available():
                misp_data["status"] = "unavailable"
                misp_data["error"] = "MISP reporter not available - check configuration"
                if request.verbose:
                    print(f"[WARNING] {misp_data['error']}")
                return misp_data

            # Filter threat results for reporting
            threat_results = [
                r for r in results if hasattr(r, "is_threat") and r.is_threat
            ]

            if not threat_results:
                misp_data["status"] = "skipped_no_threats"
                if request.verbose:
                    print("[INFO] No threats detected - skipping MISP report")
                return misp_data

            # Create MISP event
            event_result = reporter.create_event(
                target=target, results=results, session_id=self.session_id
            )

            if event_result:
                misp_data["event_id"] = event_result["event_id"]
                misp_data["uuid"] = event_result["uuid"]
                misp_data["status"] = "success"
                if request.verbose:
                    print(
                        f"[INFO] MISP event created: Event ID {event_result['event_id']} (UUID: {event_result['uuid']})"
                    )
                else:
                    print(f"MISP event created: {event_result['event_id']}")
            else:
                misp_data["status"] = "failed"
                misp_data["error"] = "Failed to create MISP event"
                if request.verbose:
                    print(f"[ERROR] {misp_data['error']}")

        except ImportError:
            misp_data["status"] = "module_unavailable"
            misp_data["error"] = "MISP integration module not available"
            if request.verbose:
                print(f"[WARNING] {misp_data['error']}")
        except Exception as e:
            misp_data["status"] = "error"
            misp_data["error"] = str(e)
            if request.verbose:
                print(f"[ERROR] MISP reporting failed: {e}")
            else:
                print(f"MISP reporting error: {e}")

        return misp_data


# Standalone functions for backward compatibility with tests
def create_argument_parser():
    """Create and return the argument parser (for test compatibility)."""
    cli = URLCheckerCLI()
    return cli.create_argument_parser()


def main():
    """Run the command-line entry point."""
    cli = URLCheckerCLI()
    cli.main()


if __name__ == "__main__":
    main()
