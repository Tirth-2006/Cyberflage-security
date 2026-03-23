# CyberFlage System Architecture

This document describes the current architecture of CyberFlage Security.

## High-Level Component Diagram

```mermaid
flowchart LR
    U[User / Operator] --> C[CLI Entry: main.py]
    C --> CFG[Config Loader\nutils.py]
    C --> APP[CyberFlage Orchestrator\ncore.py]

    APP --> DET[Threat Detector\ndetector.py]
    DET --> RS[Risk Scoring + Level Mapping]
    RS --> ACT[Action Decision\nmonitor / raise_alert / escalate / activate_decoy]

    APP --> PERSIST[Persistence Layer\nstate + feature logs]
    APP --> SIM[scripts/simulate_attack.py]

    T[tests/test_detector.py] --> DET
```

## Runtime Data Flow

```mermaid
flowchart TD
    E[Event Input] --> S[Signal]
    S --> F[Feature]
    F --> R[Risk Score]
    R --> L[Level: LOW/MEDIUM/HIGH/CRITICAL]
    L --> A[Action]
    A --> O[Output: CLI + State + Logs]
```

## Sequence (Single Run)

```mermaid
sequenceDiagram
    participant User
    participant CLI as main.py
    participant Utils as utils.py
    participant App as CyberFlage(core.py)
    participant Detector as ThreatDetector(detector.py)
    participant Persist as Persistence

    User->>CLI: Run command with config
    CLI->>Utils: load_config_file + build_config
    CLI->>App: init(config)
    CLI->>App: run_once(signals)
    App->>Detector: evaluate(signals)
    Detector-->>App: risk_score, level, action, explanation
    App-->>CLI: state dict
    CLI->>Persist: write state/features (if enabled)
    CLI-->>User: summary output
```

## Responsibilities by File

- `main.py`: command-line entry and user-facing run flow
- `cyberflage/core.py`: orchestration (`add_signal`, `run_once`)
- `cyberflage/detector.py`: scoring logic and level/action mapping
- `cyberflage/utils.py`: config defaults, merge, validation/load helpers
- `scripts/simulate_attack.py`: scenario-driven simulation runs
- `tests/test_detector.py`: detector behavior checks

## Notes for GSoC Collaborators

- Core extension points: `detector.py` (scoring/model), `core.py` (action routing), `utils.py` (config schema)
- Best ML insertion point: between `Signal -> Feature -> Risk Score`
- Keep the pipeline explainable by preserving `explanation` outputs
