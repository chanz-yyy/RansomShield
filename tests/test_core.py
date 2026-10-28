import sys, time, pytest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core import db, backup, simulator, service, report
from core.detector import detect, severity
from core.validators import validate_workspace, safe_join

def evs(t, n, dest=False): return [{"type": t, "path": f"f{i}.txt", "dest": f"f{i}.locked" if dest else None, "ts": time.time()} for i in range(n)]

def test_normal_no_alert(): assert detect(evs("modified", 2)) is None
def test_mod_burst(): assert detect(evs("modified", 12))["category"] == "Rapid modification burst"
def test_rename_and_score_range():
    d = detect(evs("moved", 30, True) + evs("modified", 30) + evs("deleted", 30)); assert 0 <= d["score"] <= 100 and d["severity"] == "Critical"
def test_severity(): assert [severity(x) for x in (0, 25, 50, 75)] == ["Low", "Medium", "High", "Critical"]
def test_protected_and_traversal(tmp_path):
    for bad in ("/", "/etc", str(Path.home())):
        with pytest.raises(ValueError): validate_workspace(bad)
    ws = validate_workspace(str(tmp_path / "ws"))
    with pytest.raises(ValueError): safe_join(ws, "../evil")

def setup(tmp_path):
    ws = validate_workspace(str(tmp_path / "ws")); simulator.generate_samples(ws, 5); c = db.connect()
    return ws, c, tmp_path / "bk"

def test_backup_restore_verified(tmp_path):
    ws, c, root = setup(tmp_path); sid = backup.create(c, ws, root); orig = backup.scan(ws)
    simulator.run(ws, "combined"); assert backup.compare(ws, root / sid)["missing"]
    r = backup.restore(c, ws, root / sid); assert r["status"] == "VERIFIED" and backup.scan(ws) == orig

def test_synthetic_delete_keeps_files(tmp_path):
    ws, c, _ = setup(tmp_path); out = simulator.run(ws, "mass_delete")
    assert len(out) == 5 and len(list(ws.glob("sample_*.txt"))) == 5

def test_corrupt_backup_fails_recovery(tmp_path):
    ws, c, root = setup(tmp_path); sid = backup.create(c, ws, root)
    (root / sid / "files" / "sample_00.txt").write_text("tampered")
    assert not backup.verify(root / sid)[0] and backup.restore(c, ws, root / sid)["status"] == "FAILED"

def test_incident_flow_and_exports():
    c = db.connect(); res = service.process(c, evs("modified", 12)); assert res
    with pytest.raises(ValueError): db.set_alert_status(c, res["alert_id"], "Resolved")
    db.set_alert_status(c, res["alert_id"], "Investigating")
    with pytest.raises(ValueError): db.set_alert_status(c, res["alert_id"], "Resolved", "")
    assert res["alert_id"] in report.table_csv(c, "alerts") and res["incident_id"] in report.to_json(report.incident_report(c, res["incident_id"]))
    assert c.execute("SELECT COUNT(*) FROM audit").fetchone()[0] >= 2

def test_detector_includes_mitre_context():
    d = detect(evs("modified", 12))
    assert d is not None
    mapping = d["rules"][0]["mitre_attack"][0]
    assert mapping["id"] == "T1565.001"
    assert mapping["name"] == "Stored Data Manipulation"
    assert mapping["url"] == "https://attack.mitre.org/techniques/T1565/001/"
