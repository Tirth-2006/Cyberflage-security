"""Simulation runner aligned with the current CyberFlage package API."""

from __future__ import annotations

from pathlib import Path

from cyberflage import CyberFlage, build_config, load_config_file


def _load_runtime_config() -> dict:
    """Load config from common locations with safe fallback."""
    candidates = [
        Path("config/config.json"),
        Path("config/config.example.json"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return build_config(load_config_file(str(candidate)))
    return build_config(None)


def _print_state(title: str, state: dict) -> None:
    print("=" * 60)
    print(title)
    print("=" * 60)
    print(f"Risk: {state['risk_score']:.2f} ({state['level']})")
    print(f"Action: {state['action']}")
    print(f"Mode: {state['mode']}")
    print("Explanation:")
    for line in state.get("explanation", []):
        print(f"- {line}")
    print()


def run_simulation() -> None:
    config = _load_runtime_config()
    app = CyberFlage(config)

    normal_signals = [
        {"type": "dns_query", "weight": 2.0},
        {"type": "web_request", "weight": 2.0},
    ]
    suspicious_signals = [
        {"type": "new_external_ip", "weight": 12.0},
        {"type": "failed_auth_burst", "weight": 14.0},
    ]
    critical_signals = [
        {"type": "suspicious_port_scan", "weight": 20.0},
        {"type": "credential_dump_attempt", "weight": 20.0},
        {"type": "mass_encrypt_pattern", "weight": 50.0},
    ]

    _print_state("Scenario: Normal Activity", app.run_once(normal_signals))
    _print_state("Scenario: Suspicious Activity", app.run_once(suspicious_signals))
    _print_state("Scenario: Critical Attack", app.run_once(critical_signals))


if __name__ == "__main__":
    run_simulation()
