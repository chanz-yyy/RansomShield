"""Background Watchdog monitor limited to the approved workspace."""
import queue, time
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from .validators import inside, MARKER

class _H(FileSystemEventHandler):
    def __init__(self, ws: Path, q): self.ws, self.q = ws, q
    def on_any_event(self, e):
        if e.is_directory or e.event_type not in ("created", "modified", "deleted", "moved"): return
        try:
            src = Path(e.src_path)
            if not inside(self.ws, src) or src.name == MARKER or src.name.endswith(".rs_tmp"): return
            dest = getattr(e, "dest_path", "") or None
            self.q.put({"type": e.event_type, "path": src.name, "dest": Path(dest).name if dest else None, "ts": time.time(), "simulated": 0})
        except Exception: pass

class Monitor:
    def __init__(self, ws: Path): self.ws, self.q, self.obs = ws, queue.Queue(), None
    @property
    def running(self) -> bool: return bool(self.obs and self.obs.is_alive())
    def start(self):
        if self.running: return
        self.obs = Observer(); self.obs.schedule(_H(self.ws, self.q), str(self.ws), recursive=True); self.obs.start()
    def stop(self):
        if self.obs: self.obs.stop(); self.obs.join(timeout=3); self.obs = None
    def drain(self) -> list[dict]:
        out = []
        while not self.q.empty(): out.append(self.q.get())
        return out
