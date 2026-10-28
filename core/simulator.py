"""Harmless ransomware-BEHAVIOUR simulator. No encryption; files are never destroyed.
Deletion is synthetic telemetry only. Renames are reversible; edits only append a marker to generated samples."""
import threading, time
from pathlib import Path
from .validators import inside
from .backup import SIM_EXT
LOCK = threading.Lock()  # prevents concurrent simulation/recovery
SCENARIOS = {
    "normal": "Normal activity: 2 ordinary edits (should NOT alert).",
    "rapid_mod": "Rapid modification burst across all sample files.",
    "mass_rename": "Mass rename to .locked_sim (reversible).",
    "mass_delete": "Synthetic deletion telemetry (no file is deleted).",
    "combined": "Modification + rename + deletion telemetry together.",
}

def generate_samples(ws: Path, n: int = 20) -> list[str]:
    names = []
    for i in range(n):
        p = ws / f"sample_{i:02d}.txt"
        if not p.exists(): p.write_text(f"RansomShield harmless sample file #{i}\n" * 5)
        names.append(p.name)
    return names

def run(ws: Path, scenario: str, cancel: threading.Event | None = None) -> list[dict]:
    """Perform scenario inside ws and return events (flagged simulated=1)."""
    if scenario not in SCENARIOS: raise ValueError("Unknown scenario")
    if not LOCK.acquire(blocking=False): raise RuntimeError("Another simulation/recovery is running")
    try:
        files = sorted(p for p in ws.glob("sample_*.txt") if p.is_file() and not p.is_symlink() and inside(ws, p))
        if not files: raise RuntimeError("No sample files; generate them first")
        ev = lambda t, p, d=None: {"type": t, "path": p.name, "dest": d, "ts": time.time(), "simulated": 1}
        out = []
        def stop(): return cancel is not None and cancel.is_set()
        if scenario == "normal":
            for p in files[:2]: p.write_text(p.read_text() + "edit\n"); out.append(ev("modified", p)); time.sleep(1)
        if scenario in ("rapid_mod", "combined"):
            for p in files:
                if stop(): break
                p.write_text(p.read_text() + "[SIM-MODIFIED]\n"); out.append(ev("modified", p))
        if scenario in ("mass_rename", "combined"):
            for p in files:
                if stop(): break
                if p.exists():
                    q = p.with_name(p.name + SIM_EXT); p.rename(q); out.append(ev("moved", p, q.name))
        if scenario in ("mass_delete", "combined"):
            out += [ev("deleted", p) for p in files]  # telemetry only
        return out
    finally: LOCK.release()
