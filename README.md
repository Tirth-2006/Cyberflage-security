# CyberFlage Security

Modular cybersecurity project with detection-focused orchestration and simulation support.

## Structure

```
Cyberflage-security/
├── cyberflage/
│   ├── __init__.py
│   ├── core.py
│   ├── detector.py
│   └── utils.py
├── scripts/
│   └── simulate_attack.py
├── config/
│   └── config.example.json
├── tests/
│   └── test_detector.py
├── main.py
├── requirements.txt
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

## Quick start

```bash
pip install -r requirements.txt
python main.py --config config/config.example.json
python scripts/simulate_attack.py
```

## Testing

```bash
pytest tests/test_detector.py
```
