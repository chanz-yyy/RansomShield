"""Backups, manifests, SHA-256 integrity, comparison and verified recovery."""
import hashlib, json, os, shutil
from pathlib import Path
from . import db
from .validators import MARKER, safe_join, inside
SIM_EXT = ".locked_sim"

def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(65536), b""): h.update(b)
    return h.hexdigest()

def scan(ws: Path) -> dict:
    """{relative path: {sha256,size}} for regular, non-symlink files inside ws."""
    out = {}
    for p in ws.rglob("*"):
        if p.is_file() and not p.is_symlink() and p.name != MARKER and inside(ws, p):
            try: out[p.relative_to(ws).as_posix()] = {"sha256": sha256(p), "size": p.stat().st_size}
            except OSError: pass
    return out

def create(c, ws: Path, root: Path) -> str:
    sid = db.uid("SNAP"); d = root / sid; (d / "files").mkdir(parents=True)
    man = scan(ws)
    for rel in man:
        dst = d / "files" / rel; dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ws / rel, dst)
    (d / "manifest.json").write_text(json.dumps({"id": sid, "created": db.now(), "files": man}, indent=1))
    ok, _ = verify(d)
    c.execute("INSERT INTO snapshots VALUES(?,?,?,?,?)", (sid, db.now(), str(d), len(man), "Verified" if ok else "FAILED"))
    db.audit(c, "backup_created", f"{sid} files={len(man)}"); return sid

def load_manifest(d: Path) -> dict:
    try: return json.loads((d / "manifest.json").read_text())["files"]
    except (OSError, ValueError, KeyError) as e: raise ValueError(f"Corrupt or missing manifest: {e}")

def verify(d: Path) -> tuple[bool, list[str]]:
    """Check every backup file against the manifest hash."""
    try: man = load_manifest(d)
    except ValueError as e: return False, [str(e)]
    bad = []
    for rel, m in man.items():
        f = d / "files" / rel
        if not f.exists(): bad.append(f"missing: {rel}")
        elif sha256(f) != m["sha256"]: bad.append(f"corrupted: {rel}")
    return (not bad), bad

def compare(ws: Path, d: Path) -> dict:
    """Added / missing / modified (and rename candidates by identical hash)."""
    man, cur = load_manifest(d), scan(ws)
    added = sorted(set(cur) - set(man)); missing = sorted(set(man) - set(cur))
    modified = sorted(r for r in set(man) & set(cur) if man[r]["sha256"] != cur[r]["sha256"])
    renamed = [(m, a) for m in missing for a in added if man[m]["sha256"] == cur[a]["sha256"]]
    return {"added": added, "missing": missing, "modified": modified, "renamed": renamed}

def restore(c, ws: Path, d: Path, only: list[str] | None = None) -> dict:
    """Restore from snapshot (source untouched), then re-verify SHA-256. Success only if all hashes match."""
    rid = db.uid("REC")
    try: man = load_manifest(d)
    except ValueError as e: return _rec(c, rid, d, 0, 0, 0, 1, "FAILED", str(e))
    targets = only or list(man)
    ok, bad = verify(d)
    if not ok: return _rec(c, rid, d, len(targets), 0, 0, len(bad), "FAILED", "Backup invalid: " + "; ".join(bad))
    restored, errors = 0, []
    for rel in targets:
        try:
            dst = safe_join(ws, rel); dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_name(dst.name + ".rs_tmp"); shutil.copy2(d / "files" / rel, tmp); os.replace(tmp, dst); restored += 1
        except (OSError, ValueError, KeyError) as e: errors.append(f"{rel}: {e}")
    if only is None:  # full restore: remove only simulator-renamed leftovers, never other files
        for p in list(ws.rglob("*" + SIM_EXT)):
            if p.is_file() and not p.is_symlink() and inside(ws, p): p.unlink()
    good = sum(1 for rel in targets if (ws / rel).exists() and sha256(ws / rel) == man[rel]["sha256"])
    mism = len(targets) - good
    status = "VERIFIED" if (good == len(targets) and not errors) else "FAILED"
    return _rec(c, rid, d, len(targets), restored, good, mism, status, "; ".join(errors))

def _rec(c, rid, d, exp, rest, ver, mis, status, detail):
    c.execute("INSERT INTO recoveries VALUES(?,?,?,?,?,?,?,?,?)", (rid, db.now(), d.name, exp, rest, ver, mis, status, detail))
    db.audit(c, "recovery", f"{rid} {status}")
    return {"id": rid, "expected": exp, "restored": rest, "verified": ver, "mismatches": mis, "status": status, "detail": detail}
