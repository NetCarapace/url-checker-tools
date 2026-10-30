#!/usr/bin/env python3
"""Comprehensive test runner for URL checker project."""

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple


class TestRunner:
    """Comprehensive test runner with detailed reporting."""

    def __init__(self, verbose: bool = False):
        """Initialize test runner."""
        self.verbose = verbose
        self.test_results: Dict[str, Dict] = {}
        self.start_time = time.time()

        # Detailed test descriptions for verbose mode
        self.test_descriptions = {
            "test_core_infrastructure.py": {
                "purpose": "Tests core system infrastructure including configuration, exceptions, and utilities",
                "key_areas": [
                    "Configuration management with environment variable overrides",
                    "Custom exception hierarchy and error handling",
                    "Input validation and sanitization",
                    "Security constraints and boundary validation",
                ],
                "importance": "Critical - ensures system stability and security fundamentals",
            },
            "test_network_api.py": {
                "purpose": "Tests network communications and API integrations",
                "key_areas": [
                    "HTTP client functionality and security validation",
                    "API key management using system keyring",
                    "Third-party API integrations (VirusTotal, URLScan, etc.)",
                    "Rate limiting and timeout handling",
                ],
                "importance": "Critical - ensures reliable external service communication",
            },
            "test_scanning_modules.py": {
                "purpose": "Tests individual scanning modules for threat detection",
                "key_areas": [
                    "YARA rule scanning for content analysis",
                    "WHOIS domain information gathering",
                    "Google Safe Browsing threat detection",
                    "Redirect chain analysis and loop detection",
                ],
                "importance": "High - core threat detection functionality",
            },
            "test_analysis_engine.py": {
                "purpose": "Tests threat intelligence synthesis and analysis logic",
                "key_areas": [
                    "Multi-source threat intelligence aggregation",
                    "Threat scoring and confidence calculation",
                    "Metadata cross-validation between providers",
                    "Result standardization and normalization",
                ],
                "importance": "High - ensures accurate threat assessment",
            },
            "test_integration.py": {
                "purpose": "Tests end-to-end workflows and component integration",
                "key_areas": [
                    "Complete scan pipeline from input to output",
                    "Component interaction and data flow",
                    "Error propagation and graceful degradation",
                    "Real-world scanning scenarios",
                ],
                "importance": "Critical - validates complete system functionality",
            },
            "test_output_formatting.py": {
                "purpose": "Tests result formatting, display, and output generation",
                "key_areas": [
                    "Human-readable result formatting",
                    "JSON output generation and structure",
                    "Content sanitization and XSS prevention",
                    "Multi-format output support (CSV, XML, etc.)",
                ],
                "importance": "Medium - ensures usable and safe output presentation",
            },
            "test_security_robustness.py": {
                "purpose": "Tests security validation and system boundaries",
                "key_areas": [
                    "Injection attack prevention (XSS, SQL, LDAP)",
                    "Input validation edge cases and malformed data",
                    "Resource limits and DoS protection",
                    "Unicode handling and homograph attacks",
                ],
                "importance": "Critical - prevents security vulnerabilities and system abuse",
            },
            "test_realistic_scanning.py": {
                "purpose": "Tests realistic scenarios using static test data and known clean sites",
                "key_areas": [
                    "YARA scanning with static malicious/benign HTML content",
                    "External service testing with proper mocking patterns",
                    "Input validation with real-world malicious inputs",
                    "Security boundary testing with documented behavior",
                ],
                "importance": "High - validates real-world usage patterns and security boundaries",
            },
            "test_cli_tools.py": {
                "purpose": "Tests CLI parser, provider configuration, and robot mode behavior (offline)",
                "key_areas": [
                    "Argument parser options and defaults",
                    "Provider enabling rules and YARA configuration",
                    "Robot mode minimal output and return code",
                    "Offline execution via monkeypatching to avoid network/filesystem",
                ],
                "importance": "High - ensures CLI stability and automation paths",
            },
        }

        # Test files and their categories
        self.test_suites = {
            "Core Infrastructure": [
                "test_base_provider_functionality.py",
                "test_cli_functionality.py",
                "test_provider_discovery.py",
                "test_robot_config_functionality.py",
            ],
            "Network & API": [
                "test_http_client_functionality.py",
            ],
            "Scanning Modules": [

            ],
            "Analysis Engine": [

            ],
            "Integration Tests": [
                "test_misp_integration_functionality.py",
            ],
            "Output & Formatting": [
                "test_results_functionality.py",
            ],
            "Security & Edge Cases": [
                "test_security_robustness.py",
            ],
            "Realistic Testing": [
                "test_realistic_scanning.py",
            ],
        }

    def run_test_suite(self, test_file: str) -> Tuple[bool, str, Dict]:
        """Run a single test suite and return results."""
        print(f"Running {test_file}...")

        # Change to tests directory to run from correct location
        test_path = Path(__file__).parent / test_file

        if not test_path.exists():
            return False, f"Test file not found: {test_file}", {}

        # Run pytest with appropriate options
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            str(test_path),
            "-v" if self.verbose else "-q",
            "--tb=short",
            "--no-header",
            "--disable-warnings",
        ]

        try:
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent,
                timeout=300,  # 5 minute timeout per test suite
            )

            duration = time.time() - start_time

            # Parse pytest output for statistics
            stats = self.parse_pytest_output(result.stdout, result.stderr)
            stats["duration"] = duration
            stats["return_code"] = result.returncode

            success = result.returncode == 0
            output = result.stdout + result.stderr

            return success, output, stats

        except subprocess.TimeoutExpired:
            return False, "Test suite timed out (5 minutes)", {"timeout": True}
        except Exception as e:
            return False, f"Error running tests: {str(e)}", {"error": str(e)}

    def parse_pytest_output(self, stdout: str, stderr: str) -> Dict:
        """Parse pytest output to extract statistics."""
        stats = {
            "passed": 0,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "warnings": 0,
        }

        # Look for pytest result line
        for line in stdout.split("\n"):
            if "passed" in line or "failed" in line:
                # Parse lines like: "5 passed, 2 failed, 1 skipped in 2.34s"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.isdigit():
                        count = int(part)
                        if i + 1 < len(parts):
                            result_type = parts[i + 1].rstrip(",")
                            if result_type in stats:
                                stats[result_type] = count

        return stats

    def extract_failed_tests(self, output: str) -> List[Tuple[str, str]]:
        """Extract failed test names and error messages from pytest output."""
        failed_tests = []
        lines = output.split("\n")

        for i, line in enumerate(lines):
            if "FAILED " in line and "::" in line:
                # Extract test name
                test_name = line.split("FAILED ")[-1].split(" ")[0]
                test_name = (
                    test_name.split("::")[-1] if "::" in test_name else test_name
                )

                # Look for error message in following lines
                error_msg = ""
                for j in range(i + 1, min(i + 10, len(lines))):
                    if (
                        lines[j].strip()
                        and not lines[j].startswith("_")
                        and "E   " in lines[j]
                    ):
                        error_msg = lines[j].strip().replace("E   ", "")
                        break

                failed_tests.append((test_name, error_msg))

        return failed_tests

    def run_all_tests(self, categories: List[str] = None) -> bool:  # noqa: C901
        """Run all test suites or specific categories."""
        print("=" * 70)
        print("URL Checker - Comprehensive Test Suite")
        print("=" * 70)
        print()

        categories_to_run = categories or list(self.test_suites.keys())
        all_success = True
        total_tests = 0
        total_passed = 0
        total_failed = 0

        for category in categories_to_run:
            if category not in self.test_suites:
                print(f"Unknown category: {category}")
                continue

            print(f"📋 {category}")
            print("-" * 50)

            for test_file in self.test_suites[category]:
                # Show detailed description in verbose mode
                if self.verbose and test_file in self.test_descriptions:
                    desc = self.test_descriptions[test_file]
                    print(f"\n🔍 {test_file}")
                    print(f"   Purpose: {desc['purpose']}")
                    print(f"   Importance: {desc['importance']}")
                    print("   Key Testing Areas:")
                    for area in desc["key_areas"]:
                        print(f"     • {area}")
                    print()

                success, output, stats = self.run_test_suite(test_file)

                self.test_results[test_file] = {
                    "success": success,
                    "output": output,
                    "stats": stats,
                    "category": category,
                }

                # Update totals
                if "passed" in stats:
                    total_tests += (
                        stats["passed"]
                        + stats.get("failed", 0)
                        + stats.get("errors", 0)
                    )
                    total_passed += stats["passed"]
                    total_failed += stats.get("failed", 0) + stats.get("errors", 0)

                # Print result
                status_icon = "✅" if success else "❌"
                duration = stats.get("duration", 0)

                print(f"  {status_icon} {test_file} ({duration:.2f}s)")

                if success and stats.get("passed", 0) > 0:
                    print(f"     Passed: {stats['passed']}")
                    if stats.get("skipped", 0) > 0:
                        print(f"     Skipped: {stats['skipped']}")
                elif not success:
                    print(f"     Failed: {stats.get('failed', 0)}")
                    if stats.get("errors", 0) > 0:
                        print(f"     Errors: {stats['errors']}")
                    all_success = False

                    # Show detailed error analysis in verbose mode
                    if self.verbose and output:
                        print("     Error output:")
                        failed_tests = self.extract_failed_tests(output)
                        if failed_tests:
                            print("     Failed test details:")
                            for test_name, error_msg in failed_tests[
                                :5
                            ]:  # Top 5 failures
                                print(f"       ❌ {test_name}")
                                if error_msg:
                                    print(f"          {error_msg[:100]}...")

                        # Show last few lines for context
                        for line in output.split("\n")[-10:]:  # Last 10 lines
                            if line.strip() and not line.startswith("="):
                                print(f"       {line}")

            print()

        # Print summary
        duration = time.time() - self.start_time
        print("=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Total Duration: {duration:.2f}s")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {total_passed}")
        print(f"Failed: {total_failed}")
        print()

        if all_success:
            print("🎉 ALL TESTS PASSED!")
        else:
            print("❌ Some tests failed. See details above.")
            print("\nFailed test suites:")
            for test_file, result in self.test_results.items():
                if not result["success"]:
                    print(f"  - {test_file}")

        print()
        return all_success

    def run_quick_tests(self) -> bool:
        """Run a quick subset of tests for fast feedback."""
        print("🚀 Running Quick Test Suite (Core + Security)")
        print("=" * 50)

        quick_categories = ["Core Infrastructure", "Security & Edge Cases"]
        return self.run_all_tests(quick_categories)

    def check_dependencies(self) -> bool:
        """Check if all test dependencies are available."""
        print("🔍 Checking test dependencies...")

        required_modules = [
            "pytest",
            "requests",
            "yara_x",
            "whois",
            "vt",
            "pylookyloo",
            "pypandora",
            "pysafebrowsing",
            "pydantic",
            "keyring",
        ]

        missing = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing.append(module)

        if missing:
            print(f"❌ Missing dependencies: {', '.join(missing)}")
            print("Install with: uv add " + " ".join(missing))
            return False
        else:
            print("✅ All dependencies available")
            return True

    def generate_coverage_report(self):
        """Generate test coverage report if coverage is available."""
        try:
            cmd = [
                sys.executable,
                "-m",
                "pytest",
                "--cov=../src/url_checker_tools",
                "--cov-report=html",
                "--cov-report=term",
                str(Path(__file__).parent),
            ]

            print("📊 Generating coverage report...")
            result = subprocess.run(
                cmd, cwd=Path(__file__).parent, capture_output=True, text=True
            )

            if result.returncode == 0:
                print("✅ Coverage report generated in htmlcov/")
            else:
                print("❌ Failed to generate coverage report")
                if self.verbose:
                    print(result.stderr)

        except FileNotFoundError:
            print("⚠️  pytest-cov not available for coverage report")


def main():
    """Main entry point for test runner."""
    parser = argparse.ArgumentParser(description="URL Checker Test Runner")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Verbose output with error details"
    )
    parser.add_argument(
        "--quick", "-q", action="store_true", help="Run quick test suite only"
    )
    parser.add_argument(
        "--category", "-c", action="append", help="Run specific test category"
    )
    parser.add_argument(
        "--check-deps", action="store_true", help="Check test dependencies only"
    )
    parser.add_argument(
        "--coverage", action="store_true", help="Generate coverage report"
    )

    args = parser.parse_args()

    runner = TestRunner(verbose=args.verbose)

    # Check dependencies first
    if args.check_deps:
        return 0 if runner.check_dependencies() else 1

    if not runner.check_dependencies():
        print("Cannot run tests without required dependencies.")
        return 1

    # Run tests
    if args.quick:
        success = runner.run_quick_tests()
    elif args.category:
        success = runner.run_all_tests(categories=args.category)
    else:
        success = runner.run_all_tests()

    # Generate coverage if requested
    if args.coverage:
        runner.generate_coverage_report()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
