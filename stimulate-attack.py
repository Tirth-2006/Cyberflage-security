import random
import time
from pathlib import Path
from typing import Any

from cyberflage.app import CyberFlage
from cyberflage.config import build_config, load_config_file


SEED = None  # Set to integer for reproducible runs


# ============================================================================
# HELPERS
# ============================================================================

def _target_folder(cf: CyberFlage) -> Path:
    """Get and create protected folder from config."""
    protected_paths = cf.config.get("protected_paths", [])
    if not protected_paths:
        raise ValueError("No protected_paths configured in config.json")
    path = Path(str(protected_paths[0])).expanduser().resolve(strict=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _cleanup_scenario(folder: Path, prefix: str, deep: bool = False) -> None:
    """Clean up files created by a scenario. If deep=True, also removes backup folders."""
    try:
        removed = 0
        # Remove files
        for file in folder.glob(f"{prefix}*.txt"):
            file.unlink()
            removed += 1
        
        # Deep cleanup: remove backup/swap folders
        if deep:
            for backup_folder in folder.glob(f"{prefix}*_backup"):
                if backup_folder.is_dir():
                    for f in backup_folder.iterdir():
                        f.unlink()
                    backup_folder.rmdir()
                    removed += 1
            for swap_folder in folder.glob(f"{prefix}*_old"):
                if swap_folder.is_dir():
                    for f in swap_folder.iterdir():
                        f.unlink()
                    swap_folder.rmdir()
                    removed += 1
        
        if removed > 0:
            print(f"✓ Cleaned up {removed} artifacts for {prefix}")
    except Exception as e:
        print(f"⚠ Cleanup warning for {prefix}: {e}")


def _create_files_safe(path: Path, prefix: str, start: int, count: int) -> int:
    """Create count files with unique names. Returns actual count created (may be less than requested)."""
    created = 0
    for i in range(start, start + count):
        try:
            (path / f"{prefix}_{i}.txt").write_text(f"payload_{prefix}_{i}\n", encoding="utf-8")
            created += 1
        except Exception:
            pass
    return created


def _rename_files_safe(path: Path, source_prefix: str, target_prefix: str, start: int, count: int) -> int:
    """Rename count files with unique names. Returns actual count renamed (may be less than requested)."""
    renamed = 0
    for i in range(start, start + count):
        try:
            source = path / f"{source_prefix}_{i}.txt"
            target = path / f"{target_prefix}_{i}.txt"
            if source.exists():
                if target.exists():
                    target.unlink()
                source.rename(target)
                renamed += 1
        except Exception:
            pass
    return renamed


def _delete_files_safe(path: Path, prefix: str, start: int, count: int) -> int:
    """Delete count files with unique names. Returns actual count deleted."""
    deleted = 0
    try:
        for i in range(start, start + count):
            target = path / f"{prefix}_{i}.txt"
            try:
                if target.exists():
                    target.unlink()
                    deleted += 1
            except Exception:
                pass
    except Exception as e:
        raise RuntimeError(f"Delete burst failed: {e}")
    return deleted


def _format_explanation(exp: Any) -> str:
    """Format explanation chain for readable output. Shows all lines if list."""
    if isinstance(exp, list) and exp:
        # Format full chain: [line1, line2, line3] → "line1 | line2 | line3"
        lines = [str(e) for e in exp if e]
        return " | ".join(lines[:3]) if lines else ""
    if isinstance(exp, str):
        return exp
    return ""

def _validate_thresholds(thresholds: dict) -> bool:
    """Validate threshold dict has required keys with sensible values."""
    required = {"MEDIUM", "HIGH", "CRITICAL"}
    if not all(k in thresholds for k in required):
        return False
    vals = sorted([thresholds[k] for k in required])
    return vals[0] < vals[1] < vals[2]


def _print_state(state: dict, cycle: int, thresholds: dict[str, float]) -> None:
    """Print risk state with correct scaling and full explanation chain."""
    score = state['risk_score']
    
    if score >= thresholds.get('CRITICAL', 85):
        color, level = "🔴", "CRITICAL"
    elif score >= thresholds.get('HIGH', 60):
        color, level = "🟠", "HIGH"
    elif score >= thresholds.get('MEDIUM', 30):
        color, level = "🟡", "MEDIUM"
    else:
        color, level = "🟢", "LOW"
    
    mode = state['mode']
    mode_icon = "🎭" if mode == "DECOY_ACTIVE" else "👁️" if mode == "MONITORING" else "⚡"
    
    print(f"\n[Cycle {cycle}] {color} Risk: {score:.1f} ({level}) | {mode_icon} {mode}")
    
    if "explanation" in state:
        exp = _format_explanation(state["explanation"])
        if exp:
            print(f"  → {exp}")
    
    if mode == "DECOY_ACTIVE":
        print(f"  ⚠️  DECOY SWAP ACTIVE - Real folder protected")


# ============================================================================
# SCENARIOS
# ============================================================================

def simulate_normal(cf: CyberFlage) -> None:
    """Baseline: Normal system activity, no threats."""
    thresholds = cf.config.get("thresholds", {})
    if not _validate_thresholds(thresholds):
        raise ValueError("Invalid threshold configuration")
    
    print("\n" + "="*70)
    print("SCENARIO 1: NORMAL TRAFFIC")
    print("="*70)
    print("Baseline monitoring with no activity.\n")
    
    for cycle in range(1, 4):
        state = cf.run_once()
        _print_state(state, cycle, thresholds)
        time.sleep(0.2)


def simulate_suspicious(cf: CyberFlage) -> None:
    """Mid-level: Gradual suspicious activity with escalation."""
    thresholds = cf.config.get("thresholds", {})
    print("\n" + "="*70)
    print("SCENARIO 2: SUSPICIOUS ACTIVITY (ESCALATING)")
    print("="*70)
    print("Gradual file creation pattern over time.\n")
    
    folder = _target_folder(cf)
    _cleanup_scenario(folder, "suspicious", deep=True)
    
    bursts = [8, 12, 15, 18, 20]
    file_counter = 1000
    
    for cycle_num, file_count in enumerate(bursts, 1):
        variance = random.randint(-2, 2)
        adjusted_count = max(1, file_count + variance)
        
        created = _create_files_safe(folder, "suspicious", file_counter, adjusted_count)
        print(f"  {cycle_num}. Created {created} files")
        file_counter += created
        
        state = cf.run_once()
        _print_state(state, cycle_num, thresholds)
        time.sleep(0.15)
    
    _cleanup_scenario(folder, "suspicious", deep=True)


def simulate_attack(cf: CyberFlage) -> None:
    """High-level: Rapid attack pattern with all operation types."""
    thresholds = cf.config.get("thresholds", {})
    print("\n" + "="*70)
    print("SCENARIO 3: CRITICAL ATTACK (RAPID ESCALATION)")
    print("="*70)
    print("Multi-phase attack: create→rename→persist→escalate.\n")
    
    folder = _target_folder(cf)
    _cleanup_scenario(folder, "attack", deep=True)
    
    file_counter = 2000
    
    # Phase 1: Initial compromise
    print("Phase 1: Initial compromise")
    count1 = random.randint(55, 65)
    created = _create_files_safe(folder, "attack", file_counter, count1)
    print(f"  Created {created} files")
    state = cf.run_once()
    _print_state(state, 1, thresholds)
    file_counter += created
    time.sleep(0.1)
    
    # Phase 2: Lateral movement
    print("\nPhase 2: Lateral movement")
    count2 = min(int(created * 0.7), random.randint(40, 50))
    rename_start = file_counter - created
    renamed = _rename_files_safe(folder, "attack", "mutated", rename_start, count2)
    print(f"  Renamed {renamed} files")
    state = cf.run_once()
    _print_state(state, 2, thresholds)
    time.sleep(0.1)
    
    # Phase 3: Persistence
    print("\nPhase 3: Persistence attempt")
    count3 = random.randint(45, 55)
    created3 = _create_files_safe(folder, "attack", file_counter, count3)
    count4 = random.randint(35, 45)
    mutate_start = rename_start
    renamed3 = _rename_files_safe(folder, "mutated", "obfuscated", mutate_start, count4)
    print(f"  Created {created3} files + Renamed {renamed3} files")
    state = cf.run_once()
    _print_state(state, 3, thresholds)
    file_counter += created3
    time.sleep(0.1)
    
    # Phase 4: Final escalation
    print("\nPhase 4: Final escalation")
    count5 = random.randint(75, 90)
    created5 = _create_files_safe(folder, "attack", file_counter, count5)
    print(f"  Created {created5} files")
    state = cf.run_once()
    _print_state(state, 4, thresholds)
    file_counter += created5
    time.sleep(0.1)
    
    # Phase 5: Decoy response
    print("\nPhase 5: System response")
    state = cf.run_once()
    _print_state(state, 5, thresholds)
    
    if state['mode'] == "DECOY_ACTIVE":
        print("\n  → Decoy is active, restoring real environment...")
        try:
            cf.deception_engine.restore_real_environment()
            print("  ✓ Real environment restored")
        except Exception as e:
            print(f"  ⚠ Restore encountered issue: {e}")
    
    _cleanup_scenario(folder, "attack", deep=True)
    _cleanup_scenario(folder, "mutated", deep=True)
    _cleanup_scenario(folder, "obfuscated", deep=True)


# ============================================================================
# MAIN
# ============================================================================

def run_all() -> None:
    """Run all scenarios in sequence with full system reset and validation."""
    print("\n╔" + "="*68 + "╗")
    print("║" + " "*12 + "CYBERFLAGE THREAT SIMULATION & DETECTION" + " "*16 + "║")
    print("║" + " "*15 + "File Detection • Risk Analysis • Response" + " "*13 + "║")
    print("╚" + "="*68 + "╝")
    
    if SEED is not None:
        random.seed(SEED)
        print(f"\n[*] Deterministic mode: seed={SEED}")
    
    try:
        config = build_config(load_config_file("config.json"))
        cf = CyberFlage(config)
        
        thresholds = cf.config.get("thresholds", {})
        if not _validate_thresholds(thresholds):
            raise ValueError(f"Invalid thresholds: {thresholds}")
        
        print("\n[✓] CyberFlage initialized")
        print(f"[✓] Protected path: {cf.config.get('protected_paths', ['?'])[0]}")
        print(f"[✓] Thresholds: MEDIUM={thresholds.get('MEDIUM')}, HIGH={thresholds.get('HIGH')}, CRITICAL={thresholds.get('CRITICAL')}")
        
        simulate_normal(cf)
        
        cf = CyberFlage(config)
        simulate_suspicious(cf)
        
        cf = CyberFlage(config)
        simulate_attack(cf)
        
        print("\n" + "="*70)
        print("SIMULATION COMPLETE")
        print("="*70)
        print("\nDemonstrated:")
        print("  ✓ Baseline vs elevated activity detection")
        print("  ✓ Risk escalation with file patterns")
        print("  ✓ Graceful degradation on partial failures")
        print("  ✓ Decoy swap activation + restoration")
        print("  ✓ Clean state transitions")
        print()
        
    except FileNotFoundError:
        print("\n❌ ERROR: config.json not found in working directory")
    except ValueError as e:
        print(f"\n❌ CONFIG ERROR: {e}")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")


if __name__ == "__main__":
    run_all()
