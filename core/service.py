"""Glue: events -> detection -> alerts -> correlated incidents -> response."""
import json, time
from . import db
from .detector import detect, DEFAULTS
CORRELATE_S = 120  # alerts within 2 minutes join the same open incident (documented strategy)
RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

def record_events(c, evs):
    c.executemany("INSERT INTO events(ts,type,path,dest,simulated) VALUES(?,?,?,?,?)",
                  [(e["ts"], e["type"], e["path"], e.get("dest"), int(e.get("simulated", 0))) for e in evs]); c.commit()

def process(c, evs, cfg=None):
    """Store events, run the real detector, create alert + (correlated) incident."""
    record_events(c, evs); d = detect(evs, cfg or DEFAULTS)
    if not d: return None
    inc = c.execute("SELECT * FROM incidents WHERE status!='Closed' AND ?-last_seen<=? ORDER BY last_seen DESC LIMIT 1",
                    (time.time(), CORRELATE_S)).fetchone()
    if inc:
        iid = inc["id"]
        sev = max(inc["severity"], d["severity"], key=RANK.get)
        c.execute("UPDATE incidents SET last_seen=?, severity=? WHERE id=?", (time.time(), sev, iid))
    else:
        iid = db.uid("INC")
        c.execute("INSERT INTO incidents(id,created,last_seen,title,severity) VALUES(?,?,?,?,?)",
                  (iid, db.now(), time.time(), f"{d['category']} detected", d["severity"]))
    aid = db.uid("ALR")
    c.execute("INSERT INTO alerts(id,created,severity,category,score,files,window,reason,evidence,recommendation,simulated,incident_id)"
              " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (aid, db.now(), d["severity"], d["category"], d["score"], d["files"], d["window"], d["reason"],
               json.dumps(d["rules"]), d["recommendation"], d["simulated"], iid))
    db.audit(c, "alert_created", f"{aid} {d['severity']} score={d['score']} incident={iid}")
    return {**d, "alert_id": aid, "incident_id": iid}

def contain(c, iid: str, undo=False):
    """SIMULATED containment only: a flag in the app. No OS/network/process changes."""
    c.execute("UPDATE incidents SET contained=?, contained_at=? WHERE id=?", (0 if undo else 1, None if undo else db.now(), iid))
    db.audit(c, "containment_undone" if undo else "containment_simulated", iid)

def add_note(c, iid, note):
    c.execute("INSERT INTO notes(ts,incident_id,note) VALUES(?,?,?)", (db.now(), iid, note)); db.audit(c, "note", iid)

def close_incident(c, iid, note):
    if not note.strip(): raise ValueError("Resolution note required")
    c.execute("UPDATE incidents SET status='Closed' WHERE id=?", (iid,)); add_note(c, iid, "CLOSED: " + note)
