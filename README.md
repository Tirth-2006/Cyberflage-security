# CyberFlage

**Understand threats. Not just detect them.**

CyberFlage is an explainable cybersecurity system that models behavior, computes risk transparently, and safely redirects attackers using decoy environments.

It is not a traditional antivirus.
It is a **behavior-driven, explainable security system** designed for learning, testing, and controlled response workflows.

---

## ⚡ Quick Start

```bash
pip install cyberflage
cyberflage start
cyberflage start --demo
```

---

## 🧠 Core Concept

CyberFlage follows a structured pipeline:

```
Event → Signal → Feature → Risk → Action
```

* **Event** → raw system activity
* **Signal** → suspicious patterns detected
* **Feature** → measurable attributes
* **Risk** → quantified score with explanation
* **Action** → safe, controlled response

---

## 🔥 What Makes CyberFlage Different

| Traditional Security Tools | CyberFlage               |
| -------------------------- | ------------------------ |
| Black-box alerts           | Explainable risk scoring |
| Reactive detection         | Behavior-driven analysis |
| Destructive responses      | Safe, reversible actions |
| Limited transparency       | Full reasoning output    |

---

## 🖥 Example Output

```bash
cyberflage start --run-once
```

```
--------------------------------
System Status
--------------------------------

Signals:
- Suspicious file burst detected

Risk Score: 67.4 (HIGH)

Action:
- Deploy active deception traps.
- Decoy environment activated successfully.

Explanation:
- Risk 52.00 -> 67.40 (+signal burst)
- +10.00 feature:signal_count
- +5.40 feature:total_signal_weight
- Risk = 67.40

Mode: DECOY_ACTIVE
--------------------------------
```

---

## 🛡 Safety First

CyberFlage is designed to be **safe by default**:

* Non-destructive mode enabled by default
* No file deletion
* Rename-based isolation (no copying/overwriting)
* Full restore capability

Even when execution is enabled, actions are **controlled and reversible**.

---

## ⚙️ How It Works

1. Monitor configured folders
2. Detect suspicious patterns
3. Compute risk score with explanation
4. Trigger safe response (if needed)
5. Optionally activate decoy environment
6. Allow full restore of original state

---

## 🧪 Demo Mode

Run a simulated scenario:

```bash
cyberflage start --demo
```

This demonstrates:

* signal generation
* risk evolution
* decision making
* response behavior

---

## 🔁 Restore Original State

If decoy mode is activated:

```bash
cyberflage restore
```

This safely restores the original environment.

---

## ⚙️ Configuration

Create a `config.json`:

```json
{
  "protected_paths": ["C:\\Users\\YourName\\Desktop\\test_folder"],
  "decoy_path": "C:\\Users\\YourName\\Desktop\\decoy_folder",
  "safety": {
    "destructive_actions_enabled": true
  }
}
```

Run with config:

```bash
cyberflage start --config-file config.json
```

---

## 📁 Project Structure

```
cyberflage/
├── core/           # decision logic, signals, risk
├── network/        # monitoring system
├── deception/      # decoy execution engine
├── alerts/         # alert handling
├── persistence/    # state saving
├── dashboard/      # optional web dashboard
```

---

## 📊 Features

* Explainable risk scoring
* Behavior-based detection
* Safe decoy execution
* Restore mechanism
* CLI workflows (start, demo, restore)
* Configurable thresholds
* Structured output for analysis

---

## 🚀 Use Cases

* Learning cybersecurity concepts
* Demonstrating behavior-based detection
* Testing defensive strategies
* Building explainable security systems

---

## 📄 Documentation

Detailed guide available:

```
Cyberflage-detailedUserGuide.pdf
```

---

## ⚠️ Disclaimer

CyberFlage is designed for **educational and research purposes**.

* Do NOT use on production systems
* Always test in controlled environments
* The author is not responsible for misuse

---

## 🧠 Philosophy

CyberFlage does not try to “block everything”.

Instead, it focuses on:

> understanding behavior → explaining risk → responding safely

---

## 👤 Author

Tirth Patel
CyberFlage Project

---

## ⭐ If you find this useful

Give the repo a star — it helps visibility and motivates further development.
