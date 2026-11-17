#!/usr/bin/env python3
"""Unified threat scoring system consolidating all scoring logic."""

from typing import Any, Dict, List

from url_checker_tools.config.scoring_config import ScoringConfig, get_scoring_config
from url_checker_tools.core.results import ProviderResult


class UnifiedThreatScorer:
    """Unified threat scoring system with consistent thresholds."""

    def __init__(self, config: ScoringConfig = None):
        """Initialize unified threat scorer with optional custom config."""
        self.config = config or get_scoring_config()

    def calculate_threat_score(self, results: List[ProviderResult]) -> Dict[str, Any]:
        """Calculate comprehensive threat score from provider results."""
        if not results:
            return self._create_empty_score()

        # Filter out error results
        valid_results = [r for r in results if not r.is_error]

        if not valid_results:
            return self._create_empty_score()

        # Calculate individual provider scores
        provider_scores = {}
        total_weighted_score = 0
        total_weight = 0
        threat_count = 0

        for result in valid_results:
            base_score = self.config.threat_level_scores.get(result.threat_level, 0)
            reliability = self.config.provider_reliability.get(result.provider, 1.0)
            confidence_factor = result.confidence

            # Calculate weighted score for this provider
            provider_score = base_score * confidence_factor * reliability
            provider_scores[result.provider] = {
                "base_score": base_score,
                "confidence": confidence_factor,
                "reliability_multiplier": reliability,
                "weighted_score": provider_score,
                "threat_level": result.threat_level.value,
                "is_threat": result.is_threat,
            }

            total_weighted_score += provider_score
            total_weight += reliability * confidence_factor

            if result.is_threat:
                threat_count += 1

        # Calculate final score (0-100 scale)
        if total_weight > 0:
            final_score = min(100, int(total_weighted_score / total_weight * 1.5))
        else:
            final_score = 0

        # Multi-provider boost
        multi_provider_boost = threat_count >= self.config.multi_provider_threshold
        if multi_provider_boost:
            final_score = min(
                100, int(final_score * self.config.multi_provider_multiplier)
            )

        # Determine verdict using unified thresholds
        verdict = self._determine_verdict(final_score)

        return {
            "final_score": final_score,
            "verdict": verdict,
            "provider_count": len(valid_results),
            "threat_count": threat_count,
            "multi_provider_boost": multi_provider_boost,
            "provider_breakdown": provider_scores,
            "score_calculation": {
                "total_weighted_score": round(total_weighted_score, 2),
                "total_weight": round(total_weight, 2),
                "multi_provider_multiplier": (
                    self.config.multi_provider_multiplier
                    if multi_provider_boost
                    else 1.0
                ),
            },
        }

    def _determine_verdict(self, score: int) -> str:
        """Determine verdict based on configured thresholds."""
        for verdict, (min_val, max_val) in self.config.verdict_thresholds.items():
            if min_val <= score <= max_val:
                return verdict
        # Fallback for scores > 100
        return "CRITICAL"

    def _create_empty_score(self) -> Dict[str, Any]:
        """Create the score used when no provider produced a result."""
        return {
            "final_score": 0,
            "verdict": "UNKNOWN",
            "provider_count": 0,
            "threat_count": 0,
            "multi_provider_boost": False,
            "provider_breakdown": {},
            "score_calculation": {
                "total_weighted_score": 0.0,
                "total_weight": 0.0,
                "multi_provider_multiplier": 1.0,
            },
        }

    def format_scoring_details(self, scoring_data: Dict[str, Any]) -> str:
        """Format scoring details for verbose output."""
        lines = [
            f"[SCORING] Final Score: {scoring_data['final_score']}/100 - {scoring_data['verdict']}",
            f"[SCORING] Providers: {scoring_data['provider_count']} total, {scoring_data['threat_count']} threats",
        ]

        if scoring_data["multi_provider_boost"]:
            lines.append("[SCORING] Multi-provider threat boost: +30%")

        lines.append("[SCORING] Provider breakdown:")
        for provider, details in scoring_data["provider_breakdown"].items():
            threat_indicator = "[THREAT]" if details["is_threat"] else "[SAFE] "
            lines.append(
                f"  {threat_indicator} {provider:12}: {details['weighted_score']:5.1f} "
                f"(base: {details['base_score']}, conf: {details['confidence']:.2f}, "
                f"rel: {details['reliability_multiplier']:.2f})"
            )

        calc = scoring_data["score_calculation"]
        lines.extend(
            [
                "[SCORING] Calculation details:",
                f"  - Weighted total: {calc['total_weighted_score']:.2f}",
                f"  - Weight sum: {calc['total_weight']:.2f}",
                f"  - Multi-provider multiplier: {calc['multi_provider_multiplier']:.2f}",
            ]
        )

        return "\n".join(lines)

    def get_threat_level_mapping(self) -> Dict[str, str]:
        """Get mapping from verdicts to threat levels for synthesis output."""
        return {
            "UNKNOWN": "unknown",
            "SAFE": "safe",
            "SUSPICIOUS": "medium",
            "MALICIOUS": "high",
            "CRITICAL": "critical",
        }

    def format_basic_score(
        self, scoring_data: Dict[str, Any], format_type: str = "human"
    ) -> str:
        """Format basic score result (for --score flag)."""
        if format_type == "json":
            result = {
                "result": {
                    "verdict": scoring_data["verdict"],
                    "threat_score": scoring_data["final_score"],
                    "metadata_confidence": min(
                        1.0, scoring_data["final_score"] / 100.0
                    ),
                    "cross_validation_status": (
                        "high_consistency"
                        if scoring_data["multi_provider_boost"]
                        else "medium_consistency"
                    ),
                }
            }
            import json

            return json.dumps(result, indent=2)
        else:
            # Human-readable format
            confidence_desc = (
                "high" if scoring_data["multi_provider_boost"] else "medium"
            )
            return f"""[SCORE] Final Score: {scoring_data['final_score']}/100 - {scoring_data['verdict']}
[SCORE] Confidence: {min(1.0, scoring_data['final_score'] / 100.0):.1%} ({confidence_desc} consistency)
[SCORE] Providers: {scoring_data['provider_count']} total, {scoring_data['threat_count']} threats"""
