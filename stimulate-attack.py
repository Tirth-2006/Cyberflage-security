import time
from pathlib import Path

from cyberflage.app import CyberFlage
from cyberflage.config import build_config, load_config_file


def _target_folder(cf: CyberFlage) -> Path:
    protected_paths = cf.config.get("protected_paths", [])
    if not protected_paths:
        raise ValueError("No protected_paths configured in config.json")
    path = Path(str(protected_paths[0])).expanduser().resolve(strict=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _create_burst(path: Path, prefix: str, count: int) -> None:
    for i in range(1, count + 1):
        (path / f"{prefix}_{i}.bat").write_text(f"echo {prefix} {i}\n", encoding="utf-8")


def _rename_burst(path: Path, source_prefix: str, target_prefix: str, count: int) -> None:
    for i in range(1, count + 1):
        source = path / f"{source_prefix}_{i}.bat"
        target = path / f"{target_prefix}_{i}.bat"
        if source.exists():
            if target.exists():
                target.unlink()
            source.rename(target)


def _delete_burst(path: Path, prefix: str, count: int) -> None:
    for i in range(1, count + 1):
        target = path / f"{prefix}_{i}.bat"
        if target.exists():
            target.unlink()


def simulate_normal(cf: CyberFlage) -> None:
    print("\n=== SCENARIO: NORMAL TRAFFIC ===")
    for i in range(3):
        state = cf.run_once()
        print(f"Cycle {i+1} | Risk: {state['risk_score']:.2f} | Mode: {state['mode']}")
        time.sleep(1)


def simulate_suspicious(cf: CyberFlage) -> None:
    print("\n=== SCENARIO: SUSPICIOUS ACTIVITY ===")
    folder = _target_folder(cf)
    _create_burst(folder, "suspicious", 20)
    for i in range(5):
        state = cf.run_once()
        print(f"Cycle {i+1} | Risk: {state['risk_score']:.2f} | Mode: {state['mode']}")
        time.sleep(0.5)


def simulate_attack(cf: CyberFlage) -> None:
    print("\n=== SCENARIO: CRITICAL ATTACK ===")
    folder = _target_folder(cf)
    _create_burst(folder, "attack", 150)
    _rename_burst(folder, "attack", "renamed", 120)
    _delete_burst(folder, "renamed", 100)
    for i in range(8):
        state = cf.run_once()
        print(f"Cycle {i+1}")
        print(f"Risk: {state['risk_score']:.2f} ({state['level']})")
        print(f"Action: {state['action']}")
        print(f"Mode: {state['mode']}")
        print("-" * 40)
        time.sleep(0.5)


def run_all() -> None:
    config = build_config(load_config_file("config.json"))
    cf = CyberFlage(config)

    simulate_normal(cf)
    simulate_suspicious(cf)
    simulate_attack(cf)

    print("\n=== DEMO COMPLETE ===")


if __name__ == "__main__":
    run_all()
