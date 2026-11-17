# Execution Flow: uv run src/url_checker_tools.py --robot --verbose --misp 'http://www.7zip.com' --sid Test

This document explains, step by step, what happens inside the codebase when you run:

uv run src/url_checker_tools.py --robot --verbose --misp 'http://www.7zip.com' --sid Test

It traces the major functions, the data that flows between them, and important branching logic. File paths and function names are provided so you can jump to the exact definitions.


## 1) Entry Point and Argument Parsing

- File: src/url_checker_tools.py
- Function: main() [lines ~1098–1279]
- Helper: create_argument_parser() [~27–190]

Flow:
1. Python executes the script’s main(), which creates an ArgumentParser via create_argument_parser(). The parser defines options for:
   - Modern provider selection (e.g., --providers, --all-providers)
   - Legacy provider flags (e.g., --virustotal, --google-sb, --yara, --all)
   - Output formatting (--format, --raw)
   - YARA configuration (--yara-rules, --yara-timeout, --yara-max-bytes)
   - Redirect analysis, file scanning options
   - Session/logging flags (--sid/--session-id, --log, --robot)
   - Integrations (--misp)
   - Provider info (--list-providers, --providers-status)
   - Verbose flag (--verbose)
2. Args are parsed from the CLI.

For our command:
- target = 'http://www.7zip.com'
- --robot = True
- --verbose = True
- --misp = True
- --sid = "Test"
- No explicit provider list; robot mode implies a reliable set of providers.


## 2) Provider Manager Setup

- File: src/url_checker_tools.py
- Location in main(): after parsing args
- Class: ProviderManager (src/url_checker_tools/providers/manager.py)

Flow:
1. Manager is created: manager = ProviderManager(verbose=args.verbose).
   - ProviderManager either uses a global ProviderRegistry (auto-discovered providers) or instantiates a fresh one. By default it uses the global registry.
2. Informational commands like --list-providers/--providers-status would be handled here, but our command doesn’t invoke those.


## 3) Provider Configuration from CLI

- File: src/url_checker_tools.py
- Function: configure_providers_from_args(args, manager) [~213–342]
- Related functions/classes:
  - ProviderConfig (src/url_checker_tools/providers/base.py)
  - setup_yara_rules() [~193–211]

Flow:
1. WHOIS is always enabled as a foundation: configs["whois"] = ProviderConfig(enabled=True).
2. Robot mode path (elif args.all or args.robot):
   - Enables reliable providers: virustotal, google_sb, lookyloo, yara (with rules), in addition to whois.
   - URLScan is intentionally omitted in robot mode due to reliability notes in the code.
   - YARA rules are resolved by setup_yara_rules(): if --yara-rules not specified, it looks for default rules under data/yara (or src/data/yara).
3. manager.enable_providers(configs) -> ProviderManager.enable_providers() -> ProviderRegistry.create_default_providers().
   - ProviderRegistry instantiates and registers providers from the auto-discovered classes with the provided configs.
4. Post-config: If YARA is enabled and the provider supports set_rules(), the rules found by setup_yara_rules() are injected.
5. Return value: enabled_providers (in robot mode it is ["whois", "virustotal", "google_sb", "lookyloo", "yara"]).

Data snapshot:
- Enabled providers: whois (always), virustotal, google_sb, lookyloo, yara.
- Provider objects are created and registered in the ProviderRegistry.


## 4) Robot Mode Execution

- File: src/url_checker_tools.py
- Function: execute_robot_mode(target_url, session_id, manager, enabled_providers, enable_misp, verbose) [~769–1095]
- Called from main() when args.robot is True and --sid is provided.

Flow:
1. Prints SID: Test. When verbose, prints the target and enabled providers.
2. Creates a ProviderScanPipeline: pipeline = ProviderScanPipeline(manager, verbose=verbose).
   - See ProviderScanPipeline in src/url_checker_tools/scanning/provider_pipeline.py.
3. Outputs a minimal “[SCAN] Checking: …” line if not verbose. Since we used --verbose, additional debugging lines appear instead.
4. Calls pipeline.scan_target(target_url, enable_synthesis=True, provider_names=enabled_providers) to perform the scans in a coordinated manner.


## 5) Provider Scan Pipeline

- File: src/url_checker_tools/scanning/provider_pipeline.py
- Class: ProviderScanPipeline
- Method: scan_target(url_or_domain, enable_synthesis, provider_names) [~53–103]

Flow:
1. Delegates to ProviderManager.scan_target() with parallel=True:
   - ProviderManager.scan_target() -> ProviderRegistry.scan_with_providers().
2. ProviderRegistry determines which providers to run:
   - If provider_names are supplied, it retrieves those providers and verifies they support the target type (URL vs domain).
3. Parallel execution behavior (src/url_checker_tools/providers/registry.py, scan_with_providers):
   - YARA is executed sequentially (thread-safety considerations).
   - Other providers (WHOIS, VT, Google SB, Lookyloo) run in a ThreadPoolExecutor.
4. Provider-level scan dispatch:
   - ProviderRegistry._safe_scan_provider(provider, target, **kwargs) routes to provider.scan_target(), deciding scan_url vs scan_domain based on provider.requires_url_format and target type.
   - Each provider returns a ThreatIntelligenceResult (src/url_checker_tools/threat_result.py) encapsulating status, detection flags, confidence, raw_response, etc.
5. Special WHOIS early exit handling (ProviderScanPipeline.scan_target):
   - WHOIS result is checked; if status=error and threat_type="domain_inactive":
     - If error indicates not found/not resolve -> raise WhoisNotFoundError
     - Else -> raise WhoisTimeoutError
   - This allows short-circuiting when the domain is definitively inactive.
6. YARA last result is stored in pipeline._last_yara_result for optional later file/download scanning.
7. If enable_synthesis=True, calls ThreatSynthesizer.synthesize(results) to produce a SynthesizedThreatAssessment.

Data snapshot:
- Results: list[ThreatIntelligenceResult] (one per provider that successfully ran).
- Optional synthesis: SynthesizedThreatAssessment with threat_level, confidence_score, risk_factors.


## 6) Provider Implementations Overview

Locations:
- WHOIS: src/url_checker_tools/providers/whois.py
- VirusTotal: src/url_checker_tools/providers/virustotal.py
- Google Safe Browsing: src/url_checker_tools/providers/google_sb.py
- Lookyloo: src/url_checker_tools/providers/lookyloo.py
- YARA: src/url_checker_tools/providers/yara.py

Highlights:
- WHOIS.scan_url() extracts netloc and calls scan_domain(); scan_domain() leverages WhoisScanner (src/url_checker_tools/scanning/whois_scanner.py). Returns an error result with domain_inactive if the domain appears inactive/not found/timeouts.
- VirusTotal.scan_url()/scan_domain() uses ApiClient.query_virustotal_*; returns ThreatIntelligenceResult.create_virustotal_result() which decodes verdict/stats into status and detection flags.
- GoogleSafeBrowsing.scan_url() uses ApiClient.query_google_safe_browsing_url() and returns create_google_sb_result(). It does not support domain-only scanning.
- Lookyloo.scan_url() uses ApiClient.query_lookyloo_url() and returns create_lookyloo_result().
- YaraProvider.scan_url() initializes YaraScanner, applies configured rules, and returns create_yara_result(). Redirect analysis details and match counts may influence the status (CLEAN/SUSPICIOUS/MALICIOUS) and threat_type/ confidence strings.


## 7) Synthesis and Robot-Mode JSONs

- Robot mode immediately converts provider results into a condensed synthesis JSON compatible with legacy formats:
  - Function: get_synthesis_json(results, session_id, target_url) [~542–591]
  - Uses CondensedSynthesizer.synthesize_condensed(threat_results) from src/url_checker_tools/analysis/threat_synthesizer.py to compute a verdict and score.
- Verdict and score are printed as: RESULT: {VERDICT} ({SCORE}/100).

Detailed JSON (provider results):
- Function: get_detailed_results_json(results, session_id, target_url) [~592–651]
- Produces an object with session_metadata and results.provider_results entries describing each provider’s outcome.

Rich synthesis builder (deprecated note in code):
- build_rich_synthesis(results, synthesis) exists for compatibility but robot mode uses get_synthesis_json() as the source of truth for the .log.


## 8) DNS Resolution and Final URL Enrichment (Robot Mode)

- File: src/url_checker_tools.py
- Functions/Sections:
  - generate_rich_detailed_log() [~432–540]
  - DNS enrichment blocks inside execute_robot_mode() after JSON creation [~931–1004 and ~1006–1086]

Flow:
1. After initial synthesis_json is created, execute_robot_mode() augments the synthesis .log structure with:
   - DNS resolution for the target domain (via DNSResolver.resolve_hostname_to_ips()).
   - IPv4/IPv6 breakdown and timestamp of the resolution.
   - Final URL tracking: If YARA raw_response contains redirect_analysis.final_url, it is added to target_info.final_url and url_change.
2. A similar DNS enrichment is applied to the detailed JSON.
3. The function generate_rich_detailed_log() shows the shape of detailed logs with session metadata and provider_results in a more human-friendly structure and also performs DNS resolution when possible.


## 9) MISP Integration (Optional via --misp)

- File: src/url_checker_tools.py
- Function: handle_threat_intelligence_integrations(synthesis_json, target_url, session_id, enable_misp, verbose, provider_results=None) [~345–430]
- Integration infrastructure: src/url_checker_tools/integrations/manager.py

Flow:
1. If --misp is provided, synthesis_json is parsed to extract verdict and score. If verdict is not SUSPICIOUS / MALICIOUS / CRITICAL, submission is skipped.
2. IntegrationManager is created; auto_discover_integrations(manager) attempts to register a MISP integration if available.
3. MISP integration is configured with values from get_config().
4. A minimal ThreatAssessment-like object is synthesized from the synthesis JSON. This is passed along with provider_results and session_id to IntegrationManager.submit_to_integrations().
5. If submission succeeds, key MISP fields (status, message, event_id/uuid/url, verdict, score) can be injected back into the synthesis JSON under session_metadata.integrations.misp.

Data snapshot:
- The integration result is a map keyed by integration name (e.g., "misp") with IntegrationResult details.


## 10) Robot Logs Creation

- File: src/url_checker_tools.py
- Function: execute_robot_mode()
- Utilities: create_logs(target_url, session_id, synthesis_json, detailed_json, base_dir) from url_checker_tools.core.session_logger

Flow:
1. After synthesis_json (".log") and detailed_json (".dlog") are finalized (including DNS/final URL enrichment and optional integration metadata), the logs are written to the configured base directory by create_logs().
2. The function returns exit codes:
   - 0 if verdict == "SAFE" (from synthesis)
   - 1 if unsafe verdict
   - 99 on unexpected exceptions


## 11) Exit Codes and Error Handling Summary

- WHOIS early exit: ProviderScanPipeline.scan_target() raises WhoisNotFoundError or WhoisTimeoutError if the domain is inactive; main() catches them and returns 2 with a user-friendly "Domain Error: ..." message (non-robot). In robot mode, the exception is handled inside execute_robot_mode() and results in a printed error and code 99 if uncaught.
- API errors (MissingAPIKeyError, APIRequestError, APIResponseError) are caught by main() with code 3 (non-robot). In robot mode, errors are printed and 99 is returned if not gracefully handled per provider.
- General URLCheckerError -> code 4 (non-robot). Unexpected exceptions -> code 99.


## 12) End-to-End Timeline for the Given Command

1. Parse args; detect robot mode, verbose, misp, sid=Test, target URL.
2. Create ProviderManager; auto-discover providers; enable whois, virustotal, google_sb, lookyloo, yara; set YARA rules.
3. execute_robot_mode(): print SID, debug info, construct ProviderScanPipeline.
4. Provider scans:
   - WHOIS (domain scanning) first check affects potential early exit.
   - VirusTotal, Google SB, Lookyloo run in parallel; YARA runs sequentially.
   - ThreatIntelligenceResult objects are collected.
5. Synthesis: get_synthesis_json() produces verdict/score JSON; print RESULT line.
6. If verbose: print human-readable summaries per provider.
7. If --misp: handle_threat_intelligence_integrations() may submit event to MISP and annotate synthesis JSON.
8. DNS and final URL enrichment of both synthesis and detailed JSON.
9. create_logs() writes .log and .dlog files.
10. Exit with 0 if SAFE; else 1. On runtime errors not handled -> 99.


## 13) Key Functions Reference

- CLI and Robot Mode:
  - src/url_checker_tools.py: main(), create_argument_parser(), configure_providers_from_args(), execute_robot_mode(), get_synthesis_json(), get_detailed_results_json(), handle_threat_intelligence_integrations(), generate_rich_detailed_log().
- Pipeline and Providers:
  - src/url_checker_tools/scanning/provider_pipeline.py: ProviderScanPipeline.scan_target().
  - src/url_checker_tools/providers/manager.py: ProviderManager.
  - src/url_checker_tools/providers/registry.py: ProviderRegistry (parallel execution, YARA sequential).
  - src/url_checker_tools/providers/{whois,virustotal,google_sb,lookyloo,yara}.py.
- Result modeling and synthesis:
  - src/url_checker_tools/threat_result.py: ThreatIntelligenceResult, ProviderType, ThreatStatus.
  - src/url_checker_tools/analysis/threat_synthesizer.py: CondensedSynthesizer, ThreatSynthesizer.
- Networking and scanning helpers:
  - src/url_checker_tools/network/api_client.py: ApiClient for VT, Google SB, Lookyloo, Pandora.
  - src/url_checker_tools/scanning/whois_scanner.py: WhoisScanner.


## 14) Notes and Edge Behaviors

- URL vs Domain targets: Registry checks provider capabilities to ensure only compatible providers run for a target type.
- YARA rules: If none are found, YARA returns an error result; the pipeline still proceeds with other providers.
- Rate limits / API keys: VT and Google SB require API keys (configured via KeyManager/Config); missing keys raise MissingAPIKeyError which is surfaced as an error result in providers that re-raise (handled by registry).
- Logging paths: Robot logs are organized under the configured logs base directory, including target hashing and timestamping (see create_logs and log_utils helpers).



## Appendix: File Role Summaries (src/url_checker_tools/ recursive)

Below is a concise, file-by-file overview of the Python modules found under src/url_checker_tools/ (recursively). Compiled __pycache__/*.pyc artifacts are excluded.

- src/url_checker_tools/__init__.py — Package initializer; exposes top-level package metadata and simplifies imports across the codebase.


- src/url_checker_tools/analysis/metadata_analyzer.py — Extracts and evaluates metadata (headers, tech signals, structural hints) to inform overall threat assessment.
- src/url_checker_tools/analysis/safe_file_analyzer.py — Heuristics for identifying potentially safe/benign file characteristics to reduce false positives.
- src/url_checker_tools/analysis/threat_synthesizer.py — Core scoring and synthesis engine (CondensedSynthesizer, ThreatSynthesizer); produces verdicts, scores, and reasoning from provider results.


- src/url_checker_tools/checker.py — Legacy/auxiliary checker orchestration (older pipeline compatibility layer and convenience routines).


- src/url_checker_tools/core/__init__.py — Core subsystem package initializer.
- src/url_checker_tools/core/config.py — Central configuration management (defaults, env overrides, file loading, accessors like get_config()).
- src/url_checker_tools/core/exceptions.py — Typed exception hierarchy (URLCheckerError, API/WHOIS/YARA-specific errors) used across modules.
- src/url_checker_tools/core/log_utils.py — Helpers for log formatting, target normalization, hashing, and metadata embedding.
- src/url_checker_tools/core/logging_config.py — Logger setup utilities (ThreatIntelLogger) and logging configuration helpers.
- src/url_checker_tools/core/scoring_config.py — Verdict level definitions and threshold configuration for scoring.
- src/url_checker_tools/core/session_logger.py — Session-aware logging utilities including create_logs() for .log/.dlog generation.
- src/url_checker_tools/core/threat_calculator.py — ThreatAssessment data model and severity-weighted scoring calculations.
- src/url_checker_tools/core/utils.py — Common helpers (URL/domain parsing, validation, general utilities).


- src/url_checker_tools/integrations/__init__.py — Integrations subsystem initializer.
- src/url_checker_tools/integrations/base.py — Base classes and data models for integrations (IntegrationResult, status enums, protocol).
- src/url_checker_tools/integrations/manager.py — IntegrationManager: registration, availability, submission routing, and result collation.
- src/url_checker_tools/integrations/misp_plugin.py — MISP integration implementation (configuration, should_report logic, submission mechanics).
- src/url_checker_tools/integrations/misp_reporter.py — Helper utilities to build and send MISP events using pymisp-compatible structures.
- src/url_checker_tools/integrations/shodan_enrichment.py — Lightweight Shodan/InternetDB enrichment routines to augment intelligence (IP ports/vulns/tags).


- src/url_checker_tools/network/__init__.py — Network subsystem initializer.
- src/url_checker_tools/network/api_client.py — Unified client for external services (VirusTotal, Google Safe Browsing, Lookyloo, Pandora); key orchestration and response parsing.
- src/url_checker_tools/network/dns_resolver.py — DNS resolution utilities to resolve hostnames to IPv4/IPv6 with error handling.
- src/url_checker_tools/network/http_client.py — Safe HTTP client wrapper (timeouts, header management, JSON handling, error propagation).
- src/url_checker_tools/network/key_manager.py — API key storage/retrieval (per service), existence checks, and secure handling.


- src/url_checker_tools/output/__init__.py — Output subsystem initializer.
- src/url_checker_tools/output/display_constants.py — Constants for display formatting (icons, labels, styles).
- src/url_checker_tools/output/result_formatter.py — Formatting utilities to render provider results and assessments for human/JSON outputs.


- src/url_checker_tools/providers/__init__.py — Providers subsystem initializer and exports.
- src/url_checker_tools/providers/_template.py — Template/skeleton for implementing a new provider consistent with the framework.
- src/url_checker_tools/providers/base.py — Abstract base classes and ProviderConfig/Capability definitions shared by all providers (and BaseHttpProvider).
- src/url_checker_tools/providers/google_sb.py — Google Safe Browsing provider; URL-only scanning via API; returns standardized ThreatIntelligenceResult.
- src/url_checker_tools/providers/lookyloo.py — Lookyloo provider; crawls/analyzes URLs and returns behavioral metadata as standardized results.
- src/url_checker_tools/providers/manager.py — High-level ProviderManager (enablement, validation, listing, delegated scans).
- src/url_checker_tools/providers/pandora.py — Pandora file-scanning provider for submitting files/URLs to analysis backend (used for download scanning paths).
- src/url_checker_tools/providers/registry.py — ProviderRegistry (class registration, auto-discovery, parallel orchestration, YARA sequencing, status).
- src/url_checker_tools/providers/urlscan.py — URLScan.io provider (URL metadata/reputation lookups; optional, API-key driven).
- src/url_checker_tools/providers/virustotal.py — VirusTotal provider for URL/domain lookups with verdict/stats mapping.
- src/url_checker_tools/providers/whois.py — WHOIS provider; domain state/age/registrar info; signals inactive domains early.
- src/url_checker_tools/providers/yara.py — YARA provider; fetches content and applies rules; exposes set_rules() and enhanced redirect-aware statuses.


- src/url_checker_tools/scanning/__init__.py — Scanning subsystem initializer.
- src/url_checker_tools/scanning/google_sb_scanner.py — Low-level Google SB scanner utility used by the provider for API interactions.
- src/url_checker_tools/scanning/provider_pipeline.py — Modern provider-based pipeline coordinating scans, WHOIS early-exit, YARA sequencing, and synthesis trigger.
- src/url_checker_tools/scanning/redirect_analyzer.py — Redirect chain analysis helpers (hop counting, suspicious patterns/indicators extraction).
- src/url_checker_tools/scanning/scan_pipeline.py — Legacy scanning pipeline retained for backward compatibility with older flows.
- src/url_checker_tools/scanning/whois_scanner.py — WHOIS scanner implementation (whois library integration, parsing, and error classification).
- src/url_checker_tools/scanning/yara_scanner.py — YARA scanner wrapper for rule compilation and URL content scanning.


- src/url_checker_toolss/threat_result.py — Canonical result models (ThreatIntelligenceResult, ProviderType, ThreatStatus, YaraMatch) used across providers and synthesis.
