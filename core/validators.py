"""Path safety: every file operation must stay inside an approved root."""
import os
from pathlib import Path

MARKER = ".ransomshield_workspace"
_BLOCK = ["/", "/etc", "/usr", "/bin", "/sbin", "/var", "/boot", "/sys", "/proc", "/dev",
          "C:\\", "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"]

def inside(base: Path, p: Path) -> bool:
    """True if p resolves (following symlinks) to a location inside base."""
    try:
        Path(os.path.realpath(p)).relative_to(Path(os.path.realpath(base)))
        return True
    except ValueError:
        return False

def validate_workspace(path: str) -> Path:
    """Return a safe workspace path or raise ValueError."""
    if not path or "\x00" in path:
        raise ValueError("Empty or invalid path")
    p = Path(os.path.realpath(Path(path).expanduser()))
    blocked = {os.path.realpath(b) for b in _BLOCK} | {os.path.realpath(Path.home())}
    if str(p) in blocked or p.parent == p:
        raise ValueError(f"Refusing protected location: {p}")
    if any(inside(Path(b), p) for b in _BLOCK[1:] if os.path.realpath(b) != os.path.realpath("/")):
        raise ValueError(f"Refusing system directory: {p}")
    if p.exists() and any(p.iterdir()) and not (p / MARKER).exists():
        raise ValueError("Folder is not empty and not a RansomShield workspace")
    p.mkdir(parents=True, exist_ok=True)
    (p / MARKER).write_text("RansomShield test workspace. Safe to monitor.\n")
    return p

def safe_join(base: Path, rel: str) -> Path:
    """Join rel to base; reject traversal / symlink escapes."""
    t = base / rel
    if not inside(base, t):
        raise ValueError(f"Path escapes workspace: {rel}")
    return t
