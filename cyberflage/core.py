"""Core orchestrator for CyberFlage."""

from __future__ import annotations

from typing import Any

from .detector import ThreatDetector


class CyberFlage:
    """Main application orchestrator."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.detector = ThreatDetector(config.get("thresholds", {}))
        self._queued_signals: list[dict[str, Any]] = []

    def add_signal(self, signal_type: str, weight: float, meta: dict[str, Any] | None = None) -> None:
        self._queued_signals.append(
            {
                "type": signal_type,
                "weight": float(weight),
                "meta": meta or {},
            }
        )

    def run_once(self, signals: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        active_signals = signals if signals is not None else self._queued_signals
        result = self.detector.evaluate(active_signals)
        self._queued_signals = []
        return {
            "risk_score": result.risk_score,
            "level": result.level,
            "action": result.action,
            "explanation": result.explanation,
            "mode": "DECOY_ACTIVE" if result.action == "activate_decoy" else "MONITORING",
        }
