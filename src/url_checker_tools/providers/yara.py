#!/usr/bin/env python3
"""Clean YARA provider implementation using new architecture."""

import glob
import os
from pathlib import Path
from typing import Dict, List

import requests

# Use yara-x only
import yara_x as yara  # type: ignore

from url_checker_tools.core.base_provider import BaseProvider
from url_checker_tools.core.results import ProviderResult, ThreatLevel

# Use yara-x TimeoutError directly
YaraTimeoutError = yara.TimeoutError


class YaraProvider(BaseProvider):
    """Clean YARA provider - only implements provider-specific logic."""

    def __init__(self, provider_name: str = "yara", config: Dict | None = None):
        """
        Initialize a YaraScanner instance with the provided configuration.

        This constructor initializes the Yara scanner by passing the given
        configuration or using a default YaraConfig if no configuration
        is provided.

        Args:
            config: Optional YaraConfig instance to set up the YaraScanner.
                If None, a default configuration will be created.

        """
        super().__init__(provider_name, config)
        self._compiled_rules = None
        self._rule_count = 0
        # Track download/scan truncation metadata
        self._truncated = False
        self._total_size = None
        self._scanned_size = None

    def is_available(self) -> bool:
        """Check if YARA is properly configured."""
        # Check if we have specific rule paths or default rules directory
        if self.config.rule_paths:
            return len(self._find_rule_files(self.config.rule_paths)) > 0

        # Primary rules directory
        rules_dir = Path(self.config.rules_dir)
        has_rules = rules_dir.exists() and (
            any(rules_dir.rglob("*.yar")) or any(rules_dir.rglob("*.yara"))
        )
        if has_rules:
            return True

        # Fallback: common test rules location (useful in dev/test environments)
        fallback_dir = Path("tests/data/yara")
        return fallback_dir.exists() and (
            any(fallback_dir.rglob("*.yar")) or any(fallback_dir.rglob("*.yara"))
        )

    def scan(self, target: str) -> ProviderResult:
        """Scan target with YARA rules."""
        # Download content if it's a URL
        if target.startswith(("http://", "https://")):
            content = self._download_content(target)
            if content is None:
                return self._create_error_result(
                    target, "Failed to download content for YARA scanning"
                )
        else:
            # Treat as domain - can't scan domains directly
            return self._create_error_result(
                target, "YARA scanning requires URLs, not domains"
            )

        # Load and compile YARA rules
        try:
            rules = self._load_yara_rules()
        except Exception as e:
            return self._create_error_result(
                target, f"Failed to load YARA rules: {str(e)}"
            )

        # Scan content
        return self._scan_content(target, content, rules)

    def _download_content(self, url: str) -> bytes:
        """Download content from URL. If larger than max_file_size, scan a truncated buffer."""
        try:
            response = requests.get(
                url,
                timeout=self.config.timeout,
                headers={"User-Agent": "url-checker-tools/1.0"},
                stream=True,
            )
            response.raise_for_status()

            # Try to respect max_file_size by streaming
            max_bytes = int(getattr(self.config, "max_file_size", 10485760) or 10485760)
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=65536):  # 64 KiB
                if not chunk:
                    continue
                remaining = max_bytes - total
                if remaining <= 0:
                    # We've reached the limit; mark truncation and stop reading
                    self._truncated = True
                    break
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    total += remaining
                    self._truncated = True
                    break
                else:
                    chunks.append(chunk)
                    total += len(chunk)
                # Soft stop if content is clearly huge
                if total >= max_bytes:
                    self._truncated = True
                    break

            content = b"".join(chunks)
            # Record sizes for details
            self._scanned_size = len(content)
            try:
                # Attempt to get total size from header if present
                self._total_size = (
                    int(response.headers.get("Content-Length"))
                    if response.headers.get("Content-Length")
                    else None
                )
            except Exception:
                self._total_size = None

            return content

        except Exception:
            return None

    def _find_rule_files(self, paths: List[str]) -> List[str]:
        """Find all YARA rule files from given paths (from old implementation)."""
        rule_files = []

        for path in paths:
            expanded_path = os.path.expanduser(path)

            # Handle glob patterns
            for matched_path in glob.glob(expanded_path):
                if os.path.isfile(matched_path):
                    if matched_path.lower().endswith((".yar", ".yara")):
                        rule_files.append(matched_path)
                elif os.path.isdir(matched_path):
                    # Recursively find rule files in directory
                    for root, _, files in os.walk(matched_path):
                        for file in files:
                            if file.lower().endswith((".yar", ".yara")):
                                rule_files.append(os.path.join(root, file))

        # Remove duplicates while preserving order
        seen = set()
        unique_files = []
        for file in rule_files:
            if file not in seen:
                unique_files.append(file)
                seen.add(file)
        return unique_files

    def _load_yara_rules(self) -> yara.Rules:
        """Load and compile YARA rules."""
        if self._compiled_rules:
            return self._compiled_rules

        # Determine rule files to use
        if self.config.rule_paths:
            rule_files = self._find_rule_files(self.config.rule_paths)
        else:
            # Use default rules directory
            rules_dir = Path(self.config.rules_dir)
            # Recursively include .yar and .yara files
            rule_files = [str(f) for f in rules_dir.rglob("*.yar")]
            rule_files += [str(f) for f in rules_dir.rglob("*.yara")]
            # Fallback to tests rules if none found in primary directory
            if not rule_files:
                fallback_dir = Path("tests/data/yara")
                rule_files = [str(f) for f in fallback_dir.rglob("*.yar")] + [
                    str(f) for f in fallback_dir.rglob("*.yara")
                ]

        if not rule_files:
            error_msg = (
                "No YARA rule files found. "
                "Ensure you have .yar or .yara files in the specified paths. "
                "Use --yara-rules to specify custom rule file or directory paths."
            )
            raise ValueError(error_msg)

        # Compile rules using yara-x API
        try:
            valid_files = []
            compile_errors = []

            # yara-x API: use Compiler
            compiler = yara.Compiler()

            for rf in rule_files:
                try:
                    with open(rf, "r", encoding="utf-8") as f:
                        rule_source = f.read()
                    compiler.add_source(rule_source)
                    valid_files.append(rf)
                except Exception as ce:
                    compile_errors.append({"file": rf, "error": str(ce)})

            if not valid_files:
                err = compile_errors[0]["error"] if compile_errors else "no rules found"
                raise ValueError(f"No valid YARA rules compiled: {err}")

            self._compiled_rules = compiler.build()
            self._rule_count = len(valid_files)

            return self._compiled_rules
        except Exception as e:
            raise ValueError(f"Failed to compile YARA rules: {e}") from e

    def _scan_content(
        self, target: str, content: bytes, rules: yara.Rules
    ) -> ProviderResult:
        """Scan content with YARA rules."""
        try:
            # Perform scan using yara-x API
            scanner = yara.Scanner(rules)
            scanner.set_timeout(self.config.scan_timeout)
            scan_results = scanner.scan(content)
            matches = scan_results.matching_rules

            if not matches:
                # No matches - content is clean
                return self._create_safe_result(
                    target,
                    {
                        "matches": [],
                        "content_size": len(content),
                        "rules_checked": self._rule_count,
                        "truncated": bool(self._truncated),
                        "scanned_bytes": (
                            self._scanned_size
                            if self._scanned_size is not None
                            else len(content)
                        ),
                        "total_size": self._total_size,
                        "scan_summary": (
                            "No pattern matches"
                            + (" (content truncated)" if self._truncated else "")
                        ),
                    },
                    confidence=0.8,
                )

            # Analyze matches
            return self._analyze_matches(target, matches, len(content))

        except YaraTimeoutError:
            return self._create_error_result(target, "YARA scan timed out")
        except Exception as e:
            return self._create_error_result(target, f"YARA scan error: {str(e)}")

    def _analyze_matches(
        self, target: str, matches: tuple, content_size: int
    ) -> ProviderResult:
        """Analyze YARA matches to determine threat level."""
        match_details = []
        threat_categories = set()
        max_severity = 0

        for rule in matches:
            # Get rule metadata - yara-x uses metadata tuple of tuples
            meta = dict(rule.metadata) if rule.metadata else {}
            category = meta.get("category", "unknown")
            severity = meta.get("severity", "medium")
            description = meta.get("description", rule.identifier)

            # Convert severity to numeric
            severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            severity_num = severity_map.get(severity.lower(), 2)
            max_severity = max(max_severity, severity_num)

            threat_categories.add(category)

            # Get pattern information
            pattern_info = []
            if rule.patterns:
                pattern_info = [str(pattern.identifier) for pattern in rule.patterns]

            match_details.append(
                {
                    "rule": rule.identifier,
                    "category": category,
                    "severity": severity,
                    "description": description,
                    "strings": pattern_info,
                    "meta": meta,
                }
            )

        # Determine threat level
        if max_severity >= 4:
            threat_level = ThreatLevel.CRITICAL
            confidence = 0.95
        elif max_severity >= 3:
            threat_level = ThreatLevel.MALICIOUS
            confidence = 0.9
        elif max_severity >= 2:
            threat_level = ThreatLevel.SUSPICIOUS
            confidence = 0.8
        else:
            threat_level = ThreatLevel.SUSPICIOUS
            confidence = 0.7

        # Build details
        details = {
            "match_count": len(matches),
            "matches": match_details,
            "threat_categories": list(threat_categories),
            "max_severity": max_severity,
            "content_size": content_size,
            "rules_matched": [rule.identifier for rule in matches],
            "truncated": bool(self._truncated),
            "scanned_bytes": (
                self._scanned_size if self._scanned_size is not None else content_size
            ),
            "scan_summary": f"{len(matches)} pattern matches found: {', '.join([rule.identifier for rule in matches])}"
            + (" (content truncated)" if self._truncated else ""),
        }

        return self._create_threat_result(
            target=target,
            threat_level=threat_level,
            details=details,
            confidence=confidence,
        )
