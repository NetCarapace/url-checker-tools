#!/usr/bin/env python3
"""Unified logging system for the new architecture."""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse


class WorkflowLogger:
    """Single unified logger for all workflow operations."""

    # Pass-through common logging methods so tests that expect a stdlib logger API don't break
    def info(self, msg: str, *args, **kwargs) -> None:
        try:
            self.logger.info(msg, *args, **kwargs)
        except Exception:
            pass

    def error(self, msg: str, *args, **kwargs) -> None:
        try:
            self.logger.error(msg, *args, **kwargs)
        except Exception:
            pass

    def debug(self, msg: str, *args, **kwargs) -> None:
        try:
            self.logger.debug(msg, *args, **kwargs)
        except Exception:
            pass

    def warning(self, msg: str, *args, **kwargs) -> None:
        try:
            self.logger.warning(msg, *args, **kwargs)
        except Exception:
            pass

    def critical(self, msg: str, *args, **kwargs) -> None:
        try:
            self.logger.critical(msg, *args, **kwargs)
        except Exception:
            pass

    def __init__(self, log_dir: str = "data/logs", session_id: Optional[str] = None):
        """Initialize workflow logging configuration.

        Set up a logger that writes JSON-formatted messages to the specified directory
        and optionally logs errors to the console.

        Args:
            log_dir: Path where the log files will be stored. Defaults to "data/logs".
            session_id: Optional session identifier used to distinguish logs from different sessions.
        """
        self.log_dir = Path(log_dir)
        self.session_id = session_id

        # Create log directory structure
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Single JSON log file for all operations
        log_file = self.log_dir / "workflow.log"

        # Set up single logger
        self.logger = logging.getLogger("workflow_logger")
        self.logger.setLevel(logging.INFO)

        # Remove existing handlers to avoid duplicates
        self.logger.handlers.clear()

        # File handler with JSON formatting
        handler = logging.FileHandler(log_file)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)

        # Console handler for errors (optional)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        self.logger.addHandler(console_handler)

        # Storage for dual logging (robot mode)
        self.provider_results = []
        self.error_logs = []
        self.synthesis_logs = []

    def _base_log_entry(self, event_type: str, **kwargs) -> Dict[str, Any]:
        """Create base log entry with common fields."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
        }

        # Add session ID if available
        if self.session_id:
            entry["session_id"] = self.session_id

        # Add additional fields
        entry.update(kwargs)

        return entry

    def log_workflow_start(
        self, workflow_id: str, target: str, providers: list
    ) -> None:
        """Log workflow initiation."""
        entry = self._base_log_entry(
            "workflow_start",
            workflow_id=workflow_id,
            target=target,
            providers=providers,
        )
        self.logger.info(json.dumps(entry))

    def log_workflow_complete(
        self, workflow_id: str, target: str, result_summary: Dict[str, Any]
    ) -> None:
        """Log workflow completion."""
        entry = self._base_log_entry(
            "workflow_complete",
            workflow_id=workflow_id,
            target=target,
            summary=result_summary,
        )
        self.logger.info(json.dumps(entry))

    def log_provider_start(self, workflow_id: str, provider: str, target: str) -> None:
        """Log individual provider scan start."""
        entry = self._base_log_entry(
            "provider_start", workflow_id=workflow_id, provider=provider, target=target
        )
        self.logger.info(json.dumps(entry))

    def log_provider_result(self, *args, **kwargs) -> None:
        """Log individual provider result - flexible signature."""
        if len(args) == 1 and hasattr(args[0], "provider"):
            # New signature: log_provider_result(provider_result)
            result = args[0]
            entry = self._base_log_entry(
                "provider_result",
                workflow_id=getattr(result, "_workflow_id", "unknown"),
                provider=result.provider,
                target=result.target,
                result={
                    "is_threat": result.is_threat,
                    "threat_level": result.threat_level.value,
                    "confidence": result.confidence,
                    "execution_time": result.execution_time,
                    "is_error": result.is_error,
                },
            )
        elif "workflow_id" in kwargs:
            # Keyword argument signature from base provider
            entry = self._base_log_entry(
                "provider_result",
                workflow_id=kwargs["workflow_id"],
                provider=kwargs["provider"],
                target=kwargs["target"],
                result=kwargs["result_summary"],
            )
        else:
            # Original positional signature
            workflow_id, provider, target, result_summary = args
            entry = self._base_log_entry(
                "provider_result",
                workflow_id=workflow_id,
                provider=provider,
                target=target,
                result=result_summary,
            )
        self.logger.info(json.dumps(entry))

    def log_request(
        self, target: str, provider: str, request_data: Dict[str, Any]
    ) -> None:
        """Log HTTP request details."""
        entry = self._base_log_entry(
            "http_request", provider=provider, target=target, request=request_data
        )
        self.logger.info(json.dumps(entry))

    def log_result(
        self, target: str, provider: str, result_data: Dict[str, Any]
    ) -> None:
        """Log HTTP response details."""
        entry = self._base_log_entry(
            "http_response", provider=provider, target=target, response=result_data
        )
        self.logger.info(json.dumps(entry))

    def log_error(
        self, target: str, provider: str, error: str, context: Dict[str, Any] = None
    ) -> None:
        """Log error details."""
        entry = self._base_log_entry(
            "error",
            provider=provider,
            target=target,
            error=error,
            context=context or {},
        )
        self.logger.error(json.dumps(entry))

    def log_synthesis(
        self, workflow_id: str, target: str, synthesis_result: Dict[str, Any]
    ) -> None:
        """Log synthesis/aggregation results."""
        entry = self._base_log_entry(
            "synthesis",
            workflow_id=workflow_id,
            target=target,
            synthesis=synthesis_result,
        )
        self.logger.info(json.dumps(entry))

    def log_early_termination(
        self, workflow_id: str, target: str, reason: str, provider: str
    ) -> None:
        """Log workflow early termination."""
        entry = self._base_log_entry(
            "early_termination",
            workflow_id=workflow_id,
            target=target,
            reason=reason,
            terminating_provider=provider,
        )
        self.logger.info(json.dumps(entry))

    def log_configuration(self, provider: str, config_summary: Dict[str, Any]) -> None:
        """Log provider configuration (without sensitive data)."""
        entry = self._base_log_entry(
            "configuration", provider=provider, config=config_summary
        )
        self.logger.info(json.dumps(entry))

    def _create_log_path(self, target: str, session_id: str) -> Tuple[Path, str]:
        """Create structured log path based on target and session."""
        target_hash = hashlib.sha256(target.lower().encode("utf-8")).hexdigest()
        date_str = datetime.now().strftime("%Y-%m-%d")

        # Sanitize session ID
        session_id_clean = re.sub(r'[<>:"/\\|?*]', "_", session_id)
        filename = f"{session_id_clean}.log"

        # Build directory path
        log_dir = self.log_dir / "sessions" / target_hash / date_str
        log_path = log_dir / filename

        return log_path, filename

    def create_dual_logs(
        self, target: str, synthesis_json: str, detailed_json: str
    ) -> Tuple[Path, Path]:
        """Create dual JSON log files (.log and .dlog) for robot mode."""
        if not self.session_id:
            raise ValueError("Session ID required for dual logging")

        # Create synthesis log (.log)
        synthesis_path, _ = self._create_log_path(target, self.session_id)
        synthesis_path.parent.mkdir(parents=True, exist_ok=True)

        with open(synthesis_path, "w", encoding="utf-8") as f:
            f.write(synthesis_json)

        # Create detailed log (.dlog) in same directory
        detailed_path = synthesis_path.with_suffix(".dlog")

        with open(detailed_path, "w", encoding="utf-8") as f:
            f.write(detailed_json)

        return synthesis_path, detailed_path

    def create_session_log(
        self,
        target: str,
        content: str,
        format_type: str = "human",
        scoring_data: dict = None,
    ) -> Path:
        """Create a single session log file (.log) for regular --log mode."""
        if not self.session_id:
            raise ValueError("Session ID required for session logging")

        # Create log file path
        log_path, _ = self._create_log_path(target, self.session_id)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        # Create session metadata
        session_metadata = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_info": self._get_target_info(target),
            "format": format_type,
        }

        # Structure the log content based on format
        if format_type in ["json", "synthesis"]:
            # JSON formats - parse and restructure
            try:
                parsed_content = json.loads(content)
                log_data = {
                    "session_metadata": session_metadata,
                    "results": parsed_content,
                }
            except json.JSONDecodeError:
                # If content isn't valid JSON, wrap it
                log_data = {"session_metadata": session_metadata, "content": content}

            # Add scoring data if available
            if scoring_data:
                log_data["scoring"] = scoring_data

            log_content = json.dumps(log_data, indent=2, ensure_ascii=False)

        else:
            # Human format - create custom format that preserves line breaks
            log_lines = []
            log_lines.append("{")
            log_lines.append(
                '  "session_metadata": '
                + json.dumps(session_metadata, indent=4).replace("\n", "\n  ").rstrip()
            )
            log_lines.append('  "content": [')

            # Split content into lines and format each as a JSON string
            content_lines = content.split("\n") if content else []
            for i, line in enumerate(content_lines):
                comma = "," if i < len(content_lines) - 1 else ""
                log_lines.append(f"    {json.dumps(line)}{comma}")

            log_lines.append("  ]")

            # Add scoring data if available
            if scoring_data:
                log_lines.append(
                    '  "scoring": '
                    + json.dumps(scoring_data, indent=4).replace("\n", "\n  ").rstrip()
                )

            log_lines.append("}")
            log_content = "\n".join(log_lines)

        with open(log_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        return log_path

    def _get_target_info(self, target: str) -> dict:
        """Get comprehensive target information matching dual log format."""
        import hashlib
        from urllib.parse import urlparse

        # Detect target type
        target_type = "url" if target.startswith(("http://", "https://")) else "domain"

        # Normalize for hashing (lowercase domain, preserve path case)
        if target_type == "url":
            try:
                parsed = urlparse(target)
                normalized = (
                    f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
                )
                if parsed.query:
                    normalized += f"?{parsed.query}"
                normalized = (
                    normalized.rstrip("/") if parsed.path in ("", "/") else normalized
                )
            except:
                normalized = target.lower()
        else:
            normalized = target.lower()

        target_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

        info = {
            "original": target,
            "normalized": normalized,
            "type": target_type,
            "hash": target_hash,
        }

        # Add URL-specific info
        if target_type == "url":
            try:
                parsed = urlparse(target)
                info.update(
                    {
                        "scheme": parsed.scheme,
                        "domain": parsed.netloc,
                        "path": parsed.path,
                        "query": parsed.query,
                    }
                )
            except:
                pass

        return info


# Global logger instance
_global_logger: Optional[WorkflowLogger] = None


def get_logger(session_id: Optional[str] = None) -> WorkflowLogger:
    """Get global logger instance."""
    global _global_logger
    if _global_logger is None or (
        _global_logger.session_id != session_id and session_id is not None
    ):
        _global_logger = WorkflowLogger(session_id=session_id)
    return _global_logger


def set_session_id(session_id: str) -> None:
    """Set session ID for global logger."""
    global _global_logger
    if _global_logger:
        _global_logger.session_id = session_id
    else:
        _global_logger = WorkflowLogger(session_id=session_id)
