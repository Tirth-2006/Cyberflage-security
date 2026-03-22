"""Threat detection and risk scoring."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class DetectionResult:
    risk_score: float
    level: str
    action: str
    explanation: list[str]


class ThreatDetector:
    def __init__(self, thresholds: dict[str, float]) -> None:
        self.thresholds = thresholds

    def evaluate(self, signals: list[dict[str, Any]]) -> DetectionResult:
        total_weight = sum(float(signal.get("weight", 0.0)) for signal in signals)
        explanation = [
            f"{signal.get('type', 'unknown')}: +{float(signal.get('weight', 0.0)):.2f}"
            for signal in signals
        ]
        explanation.insert(0, f"Total signal weight: {total_weight:.2f}")

        if total_weight >= self.thresholds.get("CRITICAL", 85.0):
            level, action = "CRITICAL", "activate_decoy"
        elif total_weight >= self.thresholds.get("HIGH", 60.0):
            level, action = "HIGH", "escalate"
        elif total_weight >= self.thresholds.get("MEDIUM", 30.0):
            level, action = "MEDIUM", "raise_alert"
        else:
            level, action = "LOW", "monitor"

        return DetectionResult(
            risk_score=total_weight,
            level=level,
            action=action,
            explanation=explanation,
        )
