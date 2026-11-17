#!/usr/bin/env python3
"""Clean, simple result system for the new architecture."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "provider": self.provider,
            "target": self.target,
            "is_threat": self.is_threat,
            "threat_level": self.threat_level.value,
            "confidence": self.confidence,
            "execution_time": self.execution_time,
            "error_message": self.error_message,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }
