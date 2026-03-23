# CyberFlage User Guide

This guide helps collaborators, mentors, and contributors set up, run, and extend CyberFlage quickly.

## 1) Project Purpose

CyberFlage is an explainable cybersecurity framework that processes runtime behavior through:

`Event -> Signal -> Feature -> Risk -> Action`

It is designed for educational, simulation, and research workflows.

## 2) Prerequisites

- Python 3.10+
- pip
- Git

Optional:
- `pytest` for tests
- virtual environment (`venv`)

## 3) Setup

### Clone

```bash
git clone https://github.com/Tirth-2006/Cyberflage-security.git
cd Cyberflage-security
```

### Create virtual environment (recommended)

```bash
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

For development:

```bash
pip install -e .
```

## 4) Configuration

Copy template:

```bash
# Windows PowerShell
Copy-Item config\config.example.json config\config.json
# Linux/macOS
cp config/config.example.json config/config.json
```

Edit `config/config.json` based on your environment.

### Key fields

- `protected_paths`: paths to monitor
- `thresholds`: MEDIUM/HIGH/CRITICAL risk boundaries
- `risk`: scoring weights and decay
- `processing`: detection limits and thresholds
- `persistence`: output paths for state and ML-ready logs
- `safety`: destructive action controls

## 5) Running CyberFlage

### Main runner

```bash
python main.py --config config/config.json
```

### Simulation script

```bash
python scripts/simulate_attack.py
```

### CLI package usage (if editable-installed)

```bash
cyberflage-security --config config/config.json
```

## 6) Outputs and Artifacts

CyberFlage persists runtime information for reproducibility and future ML integration.

- Latest state JSON:
  - `artifacts/state/cyberflage_state.json`
- Feature log CSV (append mode):
  - `data/features/cyberflage_features.csv`

Typical feature columns include:

- `saved_at_utc`
- `risk_score`
- `level`
- `action`
- `mode`
- `signal_count`
- `total_signal_weight`
- `max_signal_weight`
- `event_count`
- `signal_names`

## 7) Running Tests

```bash
pytest tests/test_detector.py
```

## 8) Troubleshooting

### Config file not found

- Ensure path is correct: `--config config/config.json`
- Verify file exists and JSON is valid

### Port/dashboard issues

- Check if configured port is already in use
- Ensure dashboard is enabled in config (if used)

### Permission errors on monitored folders

- Use folders you own
- Avoid system-protected directories

### No events detected

- Verify `protected_paths`
- Trigger activity in monitored path
- Lower thresholds for testing

## 9) Collaboration Workflow

Recommended branch flow:

1. Create feature branch
2. Add/update tests
3. Run tests locally
4. Open PR with:
   - summary
   - config impact
   - output samples

### Suggested PR checklist

- [ ] Behavior documented
- [ ] Config changes explained
- [ ] Tests added/updated
- [ ] Backward compatibility considered

## 10) GSoC-Friendly Scope Areas

High-impact extension areas:

- Adaptive threshold tuning
- Sequence-based anomaly modeling
- Alert prioritization and triage scoring
- Explainability improvements for operator decisions
- Dashboard/API integration for investigation workflows

## 11) Safety Notice

CyberFlage is intended for educational and controlled testing use.

- Do not run destructive actions on production systems.
- Do not store real credentials in config files.
- Use isolated test directories.

---

For high-level overview, start with [README.md](../README.md).
