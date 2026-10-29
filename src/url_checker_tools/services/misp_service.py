"""MISP reporting: creates a MISP event from scan results when threats were found."""

from typing import Any, List

from url_checker_tools.services.scan_request import ScanRequest


class MISPReportingService:
    """Reports scan results to MISP and returns the outcome."""

    def report(self, request: ScanRequest, results: List[Any]) -> dict:
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
                target=target, results=results, session_id=request.session_id
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
