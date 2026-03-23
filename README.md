# CyberFlage Security

A modular, deception-aware cybersecurity framework for detecting suspicious behavior, scoring risk, and triggering defensive actions.

CyberFlage Security is designed for **educational, simulation, and research use**. It helps demonstrate how modern defense systems can move beyond passive monitoring into active response strategies.

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Threat Evaluation Flow](#threat-evaluation-flow)
- [Extending the Project](#extending-the-project)
- [Roadmap](#roadmap)
- [Security & Safety Notes](#security--safety-notes)
- [Collaborator Guide](#collaborator-guide)
- [Contributing](#contributing)
- [License](#license)

## Overview

CyberFlage Security uses a modular pipeline to:

1. Ingest behavioral signals
2. Convert them into weighted risk
3. Classify threat level
4. Recommend or trigger actions

The project is intentionally structured for maintainability and extension, so you can evolve it from demo simulations to more advanced analytics and integrations.

## Key Capabilities

- **Signal-based detection model** with weighted scoring
- **Risk classification** using configurable thresholds (`MEDIUM`, `HIGH`, `CRITICAL`)
- **Action mapping** (e.g., `monitor`, `raise_alert`, `escalate`, `activate_decoy`)
- **Config-driven behavior** via JSON
- **Modular Python package** for import or CLI usage
- **Simulation script** for fast demonstration
- **Basic test coverage** for detector behavior

## Architecture

CyberFlage follows a clean modular design:

- `core.py` orchestrates app behavior
- `detector.py` handles threat evaluation logic
- `utils.py` handles config loading/building
- `scripts/simulate_attack.py` demonstrates scenario execution
- `tests/test_detector.py` validates detector outputs

This separation keeps business logic isolated from I/O and supports easy refactoring.

## Repository Structure

```text
Cyberflage-security/
│
├── cyberflage/
│   ├── __init__.py
│   ├── core.py
│   ├── detector.py
│   └── utils.py
│
├── scripts/
│   └── simulate_attack.py
│
├── config/
│   └── config.example.json
│
├── tests/
│   └── test_detector.py
│
├── docs/
│   └── UserGuide.md
│
├── main.py
├── requirements.txt
├── pyproject.toml
├── README.md
├── CONTRIBUTING.md
├── LICENSE
└── .gitignore
```

## Installation

### Prerequisites

- Python 3.10+
- `pip`

### Option A: Install dependencies only

```bash
pip install -r requirements.txt
```

### Option B: Install as editable package (recommended for development)

```bash
pip install -e .
```

## Configuration

Use the provided template:

```bash
cp config/config.example.json config/config.json
```

Then edit `config/config.json` as needed.

### Example configuration

```json
{
  "protected_paths": ["./test_folder"],
  "thresholds": {
    "MEDIUM": 30,
    "HIGH": 60,
    "CRITICAL": 85
  }
}
```

## Usage

### Run with main entry point

```bash
python main.py --config config/config.example.json
```

### Run attack simulation

```bash
python scripts/simulate_attack.py
```

### Use as an importable package

```python
from cyberflage import CyberFlage, build_config

config = build_config({
    "thresholds": {"MEDIUM": 30, "HIGH": 60, "CRITICAL": 85}
})

app = CyberFlage(config)
app.add_signal("file_create_burst", 25.0)
app.add_signal("rename_burst", 12.0)

state = app.run_once()
print(state)
```

## Testing

Run unit tests:

```bash
pytest tests/test_detector.py
```

## Threat Evaluation Flow

CyberFlage internally maps behavior using this sequence:

```text
Event -> Signal -> Risk Score -> Level -> Action
```

Where:

- **Event**: observed system behavior (e.g., burst writes)
- **Signal**: normalized detector input with weight
- **Risk Score**: aggregated signal weight
- **Level**: LOW / MEDIUM / HIGH / CRITICAL
- **Action**: monitor / raise_alert / escalate / activate_decoy

## Extending the Project

Suggested extension points:

- Add new signal types in `detector.py`
- Add new action routing in `core.py`
- Add enriched config validation in `utils.py`
- Add integration adapters (SIEM, webhook, dashboard)
- Add additional tests for edge cases and scenario coverage

## Roadmap

- Stronger anomaly models
- Streamed event ingestion
- Dashboard/API integration
- Richer persistence and audit trails
- Optional ML-assisted signal weighting

## Security & Safety Notes

- This project is for **educational/research use**.
- Do not deploy directly into production environments without hardening.
- Avoid storing secrets in plain text configs.
- Prefer environment variables or secret managers for sensitive values.

## Collaborator Guide

For contributor setup, runbooks, troubleshooting, and GSoC collaboration workflow, see:

- [`docs/UserGuide.md`](docs/UserGuide.md)

## Contributing

For PR workflow and contribution rules, see:

- [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

This project is licensed under the terms of the `LICENSE` file in this repository.
