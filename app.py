"""RansomShield - Streamlit UI. Run: streamlit run app.py"""
import json, time
from pathlib import Path
import pandas as pd, plotly.express as px, streamlit as st
from core import db, service, backup, simulator, report
from core.validators import validate_workspace
from core.detector import DEFAULTS
from core.mitre import TECHNIQUES, ATTACK_URL
import ui

st.set_page_config("RansomShield", "🛡️", layout="wide")
ui.inject()
DATA = Path("data").resolve()
DATA.mkdir(parents=True, exist_ok=True)
S = st.session_state
if "c" not in S: S.c = db.connect(str(DATA / "ransomshield.db")); S.ws = None; S.mon = None; S.cfg = dict(DEFAULTS)
c = S.c
def ws_ok():
    if S.ws is None: st.warning("Initialize a workspace first (🧪 Workspace & Demo)."); return False
    return True
def q(sql, *a): return pd.DataFrame([dict(r) for r in c.execute(sql, a)])
def pump():
    if S.mon:
        evs = S.mon.drain()
        if evs: return service.process(c, evs, S.cfg)

ui.brand()
page = st.sidebar.radio("Navigate", ["📊 Overview", "🧪 Workspace & Demo", "🚨 Alerts", "🕵️ Incidents", "💾 Backup & Recovery",
                                     "🔍 Integrity", "🧭 MITRE ATT&CK", "📜 Timeline", "📄 Reports", "⚙️ Settings"])
st.sidebar.markdown('<span class="safe">SAFE MODE: test workspace only</span>', unsafe_allow_html=True)
st.sidebar.write("Workspace:", str(S.ws) if S.ws else "— not set —")
st.sidebar.write("Monitoring:", "🟢 running" if S.mon and S.mon.running else "⚪ stopped")
pump()

if page.endswith("Overview"):
    ui.overview(q, S)

elif page.endswith("Workspace & Demo"):
    st.title("Safe Test Workspace & Guided Demo")
    path = st.text_input("Workspace path", str(DATA / "workspace"))
    if st.button("Initialize workspace"):
        try: S.ws = validate_workspace(path); db.audit(c, "workspace_init", str(S.ws)); st.success(f"Workspace: {S.ws}")
        except ValueError as ex: st.error(str(ex))
    if ws_ok():
        st.write(f"**Exact path monitored:** `{S.ws}`")
        b = st.columns(4)
        if b[0].button("Generate sample files"): st.success(f"{len(simulator.generate_samples(S.ws))} files created")
        ok = b[1].checkbox("I confirm monitoring only this folder")
        if b[2].button("Start monitoring", disabled=not ok):
            from core.monitor import Monitor
            S.mon = Monitor(S.ws); S.mon.start(); db.audit(c, "monitor_start", str(S.ws))
        if b[3].button("Stop monitoring") and S.mon: S.mon.stop(); db.audit(c, "monitor_stop")
        st.divider(); st.subheader("Attack-behaviour simulator")
        sc = st.selectbox("Scenario", list(simulator.SCENARIOS), format_func=lambda x: f"{x}: {simulator.SCENARIOS[x]}")
        st.caption("Only generated sample files inside the workspace are touched. A snapshot is required first.")
        if st.button("▶ Run simulation"):
            if not c.execute("SELECT 1 FROM snapshots").fetchone(): st.error("Create a backup first.")
            else:
                try:
                    with st.spinner("Simulating..."): evs = simulator.run(S.ws, sc)
                    res = service.process(c, evs, S.cfg); st.success(f"{len(evs)} events generated")
                    st.json(res) if res else st.info("No rule triggered (as expected for normal activity).")
                except Exception as ex: st.error(str(ex))
        st.divider(); st.subheader("Guided demo")
        if st.button("🚀 Start Guided Demo (end-to-end)"):
            log = st.container()
            simulator.generate_samples(S.ws); log.write("1-2. Workspace ready, samples generated")
            sid = backup.create(c, S.ws, DATA / "backups"); log.write(f"3. Backup {sid} created & verified")
            evs = simulator.run(S.ws, "combined"); res = service.process(c, evs, S.cfg)
            log.write(f"4-6. Simulation ran; detector raised **{res['severity']}** alert {res['alert_id']} (score {res['score']})")
            service.add_note(c, res["incident_id"], "Guided demo: reviewed evidence, simulated ransomware-like behaviour."); log.write("7. Investigated (note added)")
            service.contain(c, res["incident_id"]); log.write("8. Simulated containment applied")
            (S.ws / "sample_00.txt").write_text("controlled test change\n"); log.write("9. Controlled test-file change made")
            rec = backup.restore(c, S.ws, DATA / "backups" / sid); log.write(f"10-11. Restore: **{rec['status']}** ({rec['verified']}/{rec['expected']} hashes verified)")
            c.execute("UPDATE incidents SET recovery=? WHERE id=?", (rec["status"], res["incident_id"])); c.commit()
            S.last_report = report.incident_report(c, res["incident_id"]); log.write("12. Report generated → 📄 Reports")

elif page.endswith("Alerts"):
    st.title("Security Alerts")
    a = q("SELECT * FROM alerts ORDER BY created DESC")
    if a.empty: st.info("No alerts yet.")
    else:
        f = st.columns(3); sev = f[0].multiselect("Severity", ["Low", "Medium", "High", "Critical"]); stt = f[1].multiselect("Status", a.status.unique().tolist())
        srt = f[2].selectbox("Sort", ["Newest", "Oldest", "Highest risk"]); s = st.text_input("Search alert ID / category")
        if sev: a = a[a.severity.isin(sev)]
        if stt: a = a[a.status.isin(stt)]
        if s: a = a[a.id.str.contains(s, case=False) | a.category.str.contains(s, case=False)]
        a = a.sort_values("score", ascending=False) if srt == "Highest risk" else a.sort_values("created", ascending=(srt == "Oldest"))
        st.dataframe(a.drop(columns=["evidence"]), use_container_width=True)
        if len(a):
            aid = st.selectbox("Alert detail", a.id); row = a[a.id == aid].iloc[0]
            st.write(f"**Why:** {row.reason}"); st.write(f"**Recommended:** {row.recommendation}")
            evidence = json.loads(row.evidence)
            st.json(evidence)
            mapped = []
            for rule in evidence:
                mapped.extend(rule.get("mitre_attack", []))
            unique = {item["id"]: item for item in mapped}
            if unique:
                st.markdown("#### MITRE ATT&CK context")
                st.caption("These are contextual mappings to simulated behaviour, not proof that an ATT&CK technique occurred.")
                for technique in unique.values():
                    st.markdown(f"**{technique['id']} — {technique['name']}** · Tactic: {technique['tactic']}  \n[Official MITRE ATT&CK page]({technique['url']})")
                    st.write(technique["project_relation"])
            nxt = db.ALERT_FLOW[row.status]; ns = st.selectbox("Change status", nxt); note = st.text_input("Resolution note (required to resolve)")
            if st.button("Apply"):
                try: db.set_alert_status(c, aid, ns, note); st.rerun()
                except ValueError as ex: st.error(str(ex))

elif page.endswith("Incidents"):
    st.title("Incident Investigation & Containment")
    i = q("SELECT * FROM incidents ORDER BY created DESC")
    if i.empty: st.info("No incidents yet.")
    else:
        st.dataframe(i, use_container_width=True); iid = st.selectbox("Incident", i.id)
        st.dataframe(q("SELECT id,created,severity,category,score,status FROM alerts WHERE incident_id=?", iid), use_container_width=True)
        st.dataframe(q("SELECT ts,note FROM notes WHERE incident_id=?", iid), use_container_width=True)
        n = st.text_input("Investigation note")
        c1, c2, c3, c4 = st.columns(4)
        if c1.button("Add note") and n: service.add_note(c, iid, n); st.rerun()
        if c2.button("Simulate containment"): service.contain(c, iid); st.rerun()
        if c3.button("Undo containment"): service.contain(c, iid, undo=True); st.rerun()
        if c4.button("Close incident"):
            try: service.close_incident(c, iid, n); st.rerun()
            except ValueError as ex: st.error(str(ex))
        st.caption("⚠ Containment is SIMULATED inside this app. It does not isolate a real endpoint, network, or process.")

elif page.endswith("Backup & Recovery"):
    st.title("Backup & Recovery Center")
    if ws_ok():
        if st.button("Create baseline backup"): st.success(backup.create(c, S.ws, DATA / "backups"))
        sn = q("SELECT * FROM snapshots ORDER BY created DESC"); st.dataframe(sn, use_container_width=True)
        if len(sn):
            sid = st.selectbox("Snapshot", sn.id); d = DATA / "backups" / sid
            if st.button("Verify snapshot"): ok, bad = backup.verify(d); st.success("All hashes match") if ok else st.error(bad)
            if st.button("Compare workspace with snapshot"): st.json(backup.compare(S.ws, d))
            conf = st.checkbox("I confirm restoring files in the test workspace only")
            if st.button("Restore & verify", disabled=not conf):
                if not simulator.LOCK.acquire(blocking=False): st.error("A simulation is running")
                else:
                    try: r = backup.restore(c, S.ws, d)
                    finally: simulator.LOCK.release()
                    st.subheader("Recovery Verification Scorecard"); k = st.columns(4)
                    k[0].metric("Expected", r["expected"]); k[1].metric("Restored", r["restored"]); k[2].metric("Verified", r["verified"]); k[3].metric("Mismatches", r["mismatches"])
                    (st.success if r["status"] == "VERIFIED" else st.error)(f"Status: {r['status']} {r['detail']}")
        st.dataframe(q("SELECT * FROM recoveries ORDER BY ts DESC"), use_container_width=True)

elif page.endswith("Integrity"):
    st.title("File Integrity Scanner")
    if ws_ok():
        sn = q("SELECT id FROM snapshots ORDER BY created DESC")
        if sn.empty: st.info("Create a backup (baseline) first.")
        else:
            sid = st.selectbox("Baseline", sn.id)
            if st.button("Scan"):
                r = backup.compare(S.ws, DATA / "backups" / sid)
                st.write("A changed file is **not** proof of malicious activity.")
                st.json(r); st.download_button("Export verification report", json.dumps(r, indent=2), "integrity.json")

elif page.endswith("MITRE ATT&CK"):
    st.title("MITRE ATT&CK Mapping")
    st.markdown("RansomShield links its simulated file-activity rules to relevant MITRE ATT&CK Enterprise techniques for analyst context. These mappings are illustrative: the simulator does not encrypt or delete real files, and an alert is not proof of adversary activity.")
    st.link_button("Open official MITRE ATT&CK website", ATTACK_URL)
    st.subheader("Technique reference")
    for tid, tech in TECHNIQUES.items():
        with st.container(border=True):
            st.markdown(f"### {tech['id']} — {tech['name']}")
            st.markdown(f"**Tactic:** {tech['tactic']}  \n**Official reference:** [{tech['url']}]({tech['url']})")
            st.write(tech["description"])
            st.markdown("**How it relates to RansomShield**")
            st.write(tech["project_relation"])
            st.markdown("**Evidence represented in this project**")
            st.write(tech["evidence"])
            st.warning(tech["caveat"])
    st.caption("ATT&CK is maintained by MITRE. Technique names, descriptions and links are provided for reference; consult the official pages for the current authoritative details.")

elif page.endswith("Timeline"):
    st.title("Security Event Timeline")
    t = pd.concat([q("SELECT ts, 'file_'||type AS kind, path AS detail, simulated FROM events"),
                   q("SELECT strftime('%s',created) AS ts, 'audit_'||action AS kind, detail, 0 AS simulated FROM audit")])
    if t.empty: st.info("Nothing yet.")
    else:
        t["ts"] = pd.to_numeric(t.ts); t["time"] = pd.to_datetime(t.ts, unit="s"); k = st.multiselect("Event kinds", sorted(t.kind.unique()))
        if k: t = t[t.kind.isin(k)]
        st.dataframe(t.sort_values("ts", ascending=False)[["time", "kind", "detail", "simulated"]], use_container_width=True)

elif page.endswith("Reports"):
    st.title("Reports & Export")
    for tb in ("events", "alerts", "incidents", "audit"): st.download_button(f"CSV: {tb}", report.table_csv(c, tb), f"{tb}.csv")
    i = q("SELECT id FROM incidents")
    if len(i):
        iid = st.selectbox("Incident", i.id)
        if st.button("Generate report"): S.last_report = report.incident_report(c, iid)
    if S.get("last_report"): st.json(S.last_report); st.download_button("Download JSON report", report.to_json(S.last_report), "report.json")

else:
    st.title("Settings")
    for k_, v in list(S.cfg.items()): S.cfg[k_] = type(v)(st.number_input(k_, value=float(v), min_value=1.0))
    st.caption("Thresholds apply to the next batch of events. Lower = more sensitive = more false positives.")
    if st.button("Reset demo data (clears DB tables, not your files)"):
        for t_ in ("alerts", "notes", "incidents", "events", "recoveries", "snapshots", "audit"): c.execute(f"DELETE FROM {t_}")
        c.commit(); st.success("Database records cleared. Backup folders in data/backups are kept.")
