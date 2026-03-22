"""Simple CyberFlage simulation script."""

from __future__ import annotations

from cyberflage import CyberFlage, build_config, load_config_file


def simulate_attack() -> None:
    config = build_config(load_config_file("config/config.example.json"))
    app = CyberFlage(config)

    phases = [
        [
            {"type": "normal_io", "weight": 4},
            {"type": "normal_cpu", "weight": 3},
        ],
        [
            {"type": "file_create_burst", "weight": 28},
            {"type": "rename_burst", "weight": 14},
        ],
        [
            {"type": "mass_encrypt_pattern", "weight": 62},
            {"type": "delete_burst", "weight": 30},
        ],
    ]

    for index, signals in enumerate(phases, start=1):
        state = app.run_once(signals)
        print(f"Phase {index}")
        print(f"  Risk: {state['risk_score']:.2f} ({state['level']})")
        print(f"  Action: {state['action']}")
        print(f"  Mode: {state['mode']}")
        for line in state["explanation"]:
            print(f"    - {line}")


if __name__ == "__main__":
    simulate_attack()
