"""Utility helpers for CyberFlage."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "protected_paths": ["./test_folder"],
    "thresholds": {"MEDIUM": 30.0, "HIGH": 60.0, "CRITICAL": 85.0},
    "risk": {
        "decay_factor": 0.98,
        "signal_weight_scale": 1.0,
        "feature_weight_scale": 0.25,
        "feature_weights": {
            "signal_count": 1.0,
            "total_signal_weight": 0.2,
            "max_signal_weight": 0.1,
        },
    },
    "processing": {"max_events_per_cycle": 5000},
    "safety": {
        "destructive_actions_enabled": False,
        "destructive_acknowledged": False,
    },
}


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def build_config(raw: dict[str, Any] | None = None) -> dict[str, Any]:
    return _merge(DEFAULT_CONFIG, raw or {})


def load_config_file(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ValueError(f"Config file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as file:
        return json.load(file)
