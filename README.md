````md
# CyberFlage

CyberFlage is an educational cybersecurity project that monitors sensitive directories for suspicious filesystem activity and responds using decoy-based deception techniques.

The system detects abnormal access patterns or blacklisted processes, generates honey files, and can optionally perform atomic directory swaps to mislead potential attackers. A safe simulation mode is enabled by default.

---

## Features

- Real-time filesystem monitoring using Watchdog  
- Honey file and decoy directory generation  
- Behavioral detection (high-frequency access patterns)  
- Environmental detection (blacklisted processes)  
- Multi-channel alerting (Discord, Slack, Email, CanaryTokens)  
- Safe simulation mode (default)  
- Optional live mode with atomic directory swapping  

---

## Installation

Install required dependencies:
````
````bash
pip install watchdog psutil requests
````

---

## Usage

### Simulation Mode (Recommended)

```bash
python cyberflage.py --protected /path/to/protected --decoy /path/to/decoy
```

No filesystem changes are made in this mode.

### Live Mode (Use With Extreme Caution)

```bash
python cyberflage.py --protected /path/to/protected --decoy /path/to/decoy --allow-destructive
```

This mode renames directories and should only be used in controlled test environments.

---

## Project Structure

* `cyberflage.py` – main application logic
* `decoy/` – generated decoy and honey files (ignored by git)
* `protected/` – monitored directories (ignored by git)

---

## Disclaimer

This project is intended for **educational and research purposes only**.
Destructive mode is disabled by default.
Do **not** use on production systems.
The author is not responsible for misuse.

---

## License

This project is licensed under the MIT License.



