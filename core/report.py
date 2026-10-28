"""Reports built from real DB records."""
import csv, io, json
from . import db

def table_csv(c, table: str) -> str:
    if table not in ("events", "alerts", "incidents", "audit", "recoveries", "snapshots"): raise ValueError("bad table")
    rows = c.execute(f"SELECT * FROM {table}").fetchall(); buf = io.StringIO()
    w = csv.writer(buf)
    if rows: w.writerow(rows[0].keys())
    for r in rows: w.writerow(["'" + str(v) if str(v)[:1] in ("=", "+", "-", "@") else v for v in r])  # CSV-injection guard
    return buf.getvalue()

def incident_report(c, iid: str) -> dict:
    inc = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not inc: raise KeyError(iid)
    q = lambda s, *a: [dict(r) for r in c.execute(s, a)]
    return {"report_id": db.uid("RPT"), "generated": db.now(), "incident": dict(inc),
            "alerts": q("SELECT * FROM alerts WHERE incident_id=?", iid), "notes": q("SELECT * FROM notes WHERE incident_id=?", iid),
            "snapshots": q("SELECT * FROM snapshots ORDER BY created DESC LIMIT 1"),
            "recoveries": q("SELECT * FROM recoveries ORDER BY ts DESC LIMIT 1"), "audit": q("SELECT * FROM audit ORDER BY id"),
            "limitations": "Educational rule-based detection; simulated containment; scores are not probabilities."}

def to_json(r: dict) -> str: return json.dumps(r, indent=2, default=str)
