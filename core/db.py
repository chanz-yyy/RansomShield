"""SQLite access (parameterized queries, foreign keys, audit log)."""
import sqlite3, uuid, datetime as dt

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts REAL, type TEXT, path TEXT, dest TEXT, simulated INTEGER);
CREATE TABLE IF NOT EXISTS incidents(id TEXT PRIMARY KEY, created TEXT, last_seen REAL, title TEXT, severity TEXT,
  status TEXT DEFAULT 'Open', contained INTEGER DEFAULT 0, contained_at TEXT, recovery TEXT DEFAULT 'Not started');
CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, created TEXT, severity TEXT, category TEXT, score INTEGER,
  files INTEGER, window REAL, reason TEXT, evidence TEXT, recommendation TEXT, status TEXT DEFAULT 'New',
  simulated INTEGER, incident_id TEXT REFERENCES incidents(id));
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, ts TEXT, incident_id TEXT REFERENCES incidents(id), note TEXT);
CREATE TABLE IF NOT EXISTS snapshots(id TEXT PRIMARY KEY, created TEXT, path TEXT, files INTEGER, verified TEXT);
CREATE TABLE IF NOT EXISTS recoveries(id TEXT PRIMARY KEY, ts TEXT, snapshot TEXT, expected INTEGER, restored INTEGER,
  verified INTEGER, mismatches INTEGER, status TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts); CREATE INDEX IF NOT EXISTS ix_al_sev ON alerts(severity);
"""
ALERT_FLOW = {"New": ["Acknowledged", "Investigating"], "Acknowledged": ["Investigating", "Resolved"],
              "Investigating": ["Resolved"], "Resolved": ["Investigating"]}

def now() -> str: return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
def uid(prefix: str) -> str: return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

def connect(path: str = ":memory:") -> sqlite3.Connection:
    c = sqlite3.connect(path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); c.executescript(SCHEMA); return c

def audit(c, action: str, detail: str = "") -> None:
    c.execute("INSERT INTO audit(ts,action,detail) VALUES(?,?,?)", (now(), action, detail)); c.commit()

def set_alert_status(c, alert_id: str, new: str, note: str = "") -> None:
    """Validated status transition; resolving requires a note."""
    row = c.execute("SELECT status FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not row: raise KeyError(alert_id)
    if new not in ALERT_FLOW.get(row["status"], []): raise ValueError(f"{row['status']} -> {new} not allowed")
    if new == "Resolved" and not note.strip(): raise ValueError("Resolution note required")
    c.execute("UPDATE alerts SET status=? WHERE id=?", (new, alert_id))
    audit(c, "alert_status", f"{alert_id}: {row['status']} -> {new} {note}")
