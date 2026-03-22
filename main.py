"""CLI entry point for CyberFlage."""

from __future__ import annotations

import argparse

from cyberflage import CyberFlage, build_config, load_config_file


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberFlage security runner")
    parser.add_argument("--config", default="config/config.example.json", help="Path to config file")
    args = parser.parse_args()

    config = build_config(load_config_file(args.config))
    app = CyberFlage(config)

    demo_signals = [
        {"type": "file_create_burst", "weight": 25.0},
        {"type": "rename_burst", "weight": 12.0},
    ]

    state = app.run_once(demo_signals)
    print("CyberFlage run summary")
    print(f"Risk: {state['risk_score']:.2f} ({state['level']})")
    print(f"Action: {state['action']}")


if __name__ == "__main__":
    main()
