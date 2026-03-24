# CyberFlage Security

A modular, deception-aware cybersecurity framework for detecting suspicious behavior, scoring risk, and triggering defensive actions.

CyberFlage Security is designed for **educational, simulation, and research use**. It demonstrates how modern defense can move from passive monitoring to explainable, action-oriented response.

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
- [Roadmap](#roadmap)
- [Security & Safety Notes](#security--safety-notes)
- [Collaborator Guide](#collaborator-guide)
- [Contributing](#contributing)
- [License](#license)

## Overview

CyberFlage Security uses a clear pipeline to convert activity into response:

1. Ingest behavioral signals
2. Compute weighted risk
3. Classify threat level
4. Recommend or trigger action

This design keeps the project maintainable, explainable, and easy to extend for GSoC-sized work.

## Key Capabilities

- Signal-based detection with weighted scoring
- Configurable thresholds (`MEDIUM`, `HIGH`, `CRITICAL`)
- Action mapping (`monitor`, `raise_alert`, `escalate`, `activate_decoy`)
- Config-driven behavior via JSON
- Importable Python package
- Scenario simulation script for fast demos
- Unit tests for detector behavior

## Architecture

Core modules:

- `core.py`: orchestrator (`add_signal`, `run_once`)
- `detector.py`: risk evaluation and action decision
- `utils.py`: config loading and build helpers
- `scripts/simulate_attack.py`: runnable scenarios
- `tests/test_detector.py`: detector tests

Diagram:

- [`docs/SystemArchitecture.md`](docs/SystemArchitecture.md)

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
│   ├── UserGuide.md
│   └── SystemArchitecture.md
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

### Install dependencies

```bash
pip install -r requirements.txt
```

### Editable install (recommended for development)

```bash
pip install -e .
```

## Configuration

Copy the template:

```bash
cp config/config.example.json config/config.json
```

Windows PowerShell:

```powershell
Copy-Item config\config.example.json config\config.json
```

Then edit `config/config.json` as needed.

## Usage

### Main runner

```bash
python main.py --config config/config.json
```

### Simulation

```bash
python scripts/simulate_attack.py
```

### Package CLI (after install)

```bash
cyberflage-security --config config/config.json
```

### Import usage

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

```bash
pytest tests/test_detector.py
```

## Threat Evaluation Flow

```text
Event -> Signal -> Risk Score -> Level -> Action
```

- **Event**: observed behavior (example: burst writes)
- **Signal**: normalized weighted input
- **Risk Score**: aggregated signal weight
- **Level**: LOW / MEDIUM / HIGH / CRITICAL
- **Action**: monitor / raise_alert / escalate / activate_decoy

## Roadmap

- Sequence-based anomaly modeling
- Adaptive threshold tuning
- Dashboard/API integration
- Richer persistence and audit logs
- Optional ML-assisted scoring

## Security & Safety Notes

- Educational/research project (not production-ready by default)
- Do not run destructive workflows on production assets
- Do not store secrets in plain JSON configs
- Use controlled test directories

## Collaborator Guide

- [`docs/UserGuide.md`](docs/UserGuide.md)

## Contributing

- [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

Licensed under the terms in [`LICENSE`](LICENSE).
