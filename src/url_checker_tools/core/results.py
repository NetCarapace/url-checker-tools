#!/usr/bin/env python3
"""Clean, simple result system for the new architecture."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatLevel(Enum):
    """Standardized threat levels."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    ERROR = "error"


class ActionRecommendation(Enum):
    """Automated system actions."""

    ALLOW = "allow"
    FLAG_FOR_REVIEW = "flag_for_review"
    BLOCK = "block"
    QUARANTINE = "quarantine"


@dataclass(slots=True)
class ProviderResult:
    """Clean, simple result from a single provider."""

    provider: str
    target: str
    is_threat: bool
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    details: Dict[str, Any]
    timestamp: Optional[datetime] = field(default=None)
    execution_time: Optional[float] = field(default=None)  # seconds
    error_message: Optional[str] = field(default=None)

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

    @property
    def is_error(self) -> bool:
        """Check if this result represents an error."""
        return self.threat_level == ThreatLevel.ERROR or self.error_message is not None

    @property
    def is_unavailable(self) -> bool:
        """Check if the provider did not run because it is not configured."""
        return self.is_error and self.details.get("status") == "unavailable"

    @property
    def is_actionable_threat(self) -> bool:
        """Check if this represents a threat that requires action."""
        return self.threat_level in [ThreatLevel.MALICIOUS, ThreatLevel.CRITICAL]


@dataclass(slots=True)
class WorkflowResult:
    """Aggregated results from all providers in a workflow."""

    workflow_id: str
    target: str
    results: List[ProviderResult]
    final_assessment: ThreatLevel
    recommendation: ActionRecommendation
    confidence_score: float  # Aggregated confidence
    started_at: datetime
    completed_at: Optional[datetime]
    total_execution_time: Optional[float]

    @property
    def is_completed(self) -> bool:
        """Check if workflow is completed."""
        return self.completed_at is not None

    @property
    def provider_count(self) -> int:
        """Number of providers that ran."""
        return len(self.results)

    @property
    def error_count(self) -> int:
        """Number of providers that errored."""
        return sum(1 for result in self.results if result.is_error)

    @property
    def threat_detections(self) -> List[ProviderResult]:
        """Get all results that detected threats."""
        return [
            result
            for result in self.results
            if result.is_threat and not result.is_error
        ]

    def mark_completed(self) -> None:
        """Mark workflow as completed."""
        self.completed_at = datetime.now(timezone.utc)
        if self.started_at:
            self.total_execution_time = (
                self.completed_at - self.started_at
            ).total_seconds()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "workflow_id": self.workflow_id,
            "target": self.target,
            "final_assessment": self.final_assessment.value,
            "recommendation": self.recommendation.value,
            "confidence_score": self.confidence_score,
            "provider_count": self.provider_count,
            "error_count": self.error_count,
            "threat_detections": len(self.threat_detections),
            "started_at": self.started_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "total_execution_time": self.total_execution_time,
            "results": [
                {
                    "provider": result.provider,
                    "is_threat": result.is_threat,
                    "threat_level": result.threat_level.value,
                    "confidence": result.confidence,
                    "execution_time": result.execution_time,
                    "error_message": result.error_message,
                    "timestamp": result.timestamp.isoformat(),
                }
                for result in self.results
            ],
        }
