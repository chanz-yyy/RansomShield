"""RansomShield theme + SOC-style overview dashboard."""
import html as H, time
import pandas as pd, plotly.express as px, plotly.graph_objects as go, streamlit as st

SEV = {"Low": "#38bdf8", "Medium": "#facc15", "High": "#fb923c", "Critical": "#f43f5e"}
CSS = """<style>
html,body,[class*="css"]{font-family:'Inter','Segoe UI',sans-serif}
.stApp{background:radial-gradient(1100px 560px at 8% -8%,#17295a 0%,#0a1020 55%,#070b16 100%);color:#dbe4f3}
section[data-testid=stSidebar]{background:linear-gradient(180deg,#0f1a38,#0a1124);border-right:1px solid #1f2d52}
.block-container{padding-top:1.2rem;max-width:1400px}
h1,h2,h3{color:#e8f1ff;letter-spacing:-.02em}
.brand{font-size:1.45rem;font-weight:800;background:linear-gradient(90deg,#22d3ee,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.sub{color:#8fa3c7;font-size:.8rem;margin-bottom:.6rem}
.safe{background:rgba(16,185,129,.15);color:#6ee7b7;border:1px solid #10b98155;padding:5px 12px;border-radius:999px;font-size:.78rem;font-weight:600;display:inline-block}
.hero{background:linear-gradient(120deg,#112250 0%,#1b2f6e 45%,#3b2a7a 100%);border:1px solid #2c3f7a;border-radius:18px;padding:22px 26px;margin-bottom:16px;box-shadow:0 0 40px rgba(99,102,241,.18)}
.hero h1{margin:0;font-size:1.9rem}.hero p{margin:.3rem 0 .9rem;color:#b6c4e6}
.chip{display:inline-block;margin:0 8px 6px 0;padding:4px 12px;border-radius:999px;background:#0b1430aa;border:1px solid #2c3f7a;color:#cfe0ff;font-size:.78rem}
.kpi{background:linear-gradient(150deg,#131f40,#0e1731);border:1px solid #243662;border-top:3px solid var(--c);border-radius:14px;padding:14px 16px;height:100%}
.kpi .l{color:#8fa3c7;font-size:.74rem;text-transform:uppercase;letter-spacing:.08em}
.kpi .v{font-size:2rem;font-weight:800;color:#fff;line-height:1.15}.kpi .s{color:#7d90b8;font-size:.72rem}
.badge{padding:2px 10px;border-radius:999px;font-size:.72rem;font-weight:700;color:#0a1020;background:var(--c)}
.tbl{width:100%;border-collapse:collapse;font-size:.82rem}.tbl th{color:#8fa3c7;text-align:left;font-weight:600;padding:8px;border-bottom:1px solid #223158}
.tbl td{padding:8px;border-bottom:1px solid #1a2647;color:#dbe4f3}
.icard{background:#101a36;border:1px solid #243662;border-left:4px solid var(--c);border-radius:12px;padding:12px 14px;margin-bottom:10px}
.icard b{color:#fff}.next{color:#67e8f9;font-size:.8rem;margin-top:4px}
.feed{font-family:Consolas,monospace;font-size:.78rem;color:#a9bbdf;padding:3px 0;border-bottom:1px dashed #1c2a50}
.empty{background:#0f1a36;border:1px dashed #34487f;border-radius:14px;padding:22px;text-align:center;color:#9fb2d9}
div[data-testid=stVerticalBlockBorderWrapper]{background:#0f1830aa;border-color:#223158!important;border-radius:14px}
div[data-testid=stMetric]{background:#121c35;border:1px solid #223158;border-radius:12px;padding:10px}
.stButton>button{border-radius:10px;border:1px solid #3b4f91;background:linear-gradient(135deg,#1d2f68,#2b2a72);color:#fff;font-weight:600}
.stButton>button:hover{border-color:#22d3ee;box-shadow:0 0 14px rgba(34,211,238,.35);color:#fff}
@media(max-width:700px){.hero h1{font-size:1.35rem}.kpi .v{font-size:1.5rem}}
</style>"""

def inject(): st.markdown(CSS, unsafe_allow_html=True)
def brand():
    st.sidebar.markdown('<div class="brand">🛡️ RansomShield</div><div class="sub">Ransomware behaviour detection &amp; recovery simulator · educational</div>', unsafe_allow_html=True)
def badge(t, c): return f'<span class="badge" style="--c:{c}">{H.escape(str(t))}</span>'
def kpi(l, v, s, c): return f'<div class="kpi" style="--c:{c}"><div class="l">{l}</div><div class="v">{v}</div><div class="s">{s}</div></div>'
def style(fig, h=280):
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#cbd5e1", height=h,
                      margin=dict(l=10, r=10, t=44, b=10), legend=dict(orientation="h", y=-0.15), title_font_size=14)
    fig.update_xaxes(gridcolor="#1c2a50"); fig.update_yaxes(gridcolor="#1c2a50"); return fig
def nxt(row):
    if not row.contained: return "Simulate containment, then review evidence"
    if row.recovery == "Not started": return "Restore from a verified clean backup"
    if row.recovery == "VERIFIED": return "Recovery verified, close with a resolution note"
    return "Recovery failed: investigate backup integrity"

def overview(q, S):
    a, e, i, r = q("SELECT * FROM alerts"), q("SELECT * FROM events"), q("SELECT * FROM incidents"), q("SELECT * FROM recoveries ORDER BY ts DESC LIMIT 1")
    mon = bool(S.mon and S.mon.running)
    files = sum(1 for p in S.ws.rglob("*") if p.is_file() and not p.name.startswith(".ransom")) if S.ws else 0
    last = time.strftime("%H:%M:%S", time.localtime(e.ts.max())) if len(e) else "no events yet"
    st.markdown(f'<div class="hero"><h1>🛡️ Security Operations Overview</h1><p>Monitor → Detect → Alert → Investigate → Contain → Recover → Verify → Report</p>'
                f'<span class="chip">🟢 SAFE MODE · test workspace only</span><span class="chip">{"🟢 Monitoring ON" if mon else "⚪ Monitoring OFF"}</span>'
                f'<span class="chip">📁 {H.escape(str(S.ws)) if S.ws else "workspace not set"}</span><span class="chip">🕒 Last event: {last}</span></div>', unsafe_allow_html=True)
    f1, f2, _ = st.columns([1.3, 1, 2])
    sev = f1.multiselect("Severity filter", list(SEV)); rng = f2.selectbox("Time range", ["All time", "Last 15 min", "Last hour", "Last 24 h"])
    mins = {"Last 15 min": 15, "Last hour": 60, "Last 24 h": 1440}.get(rng)
    if mins:
        cut = time.time() - mins * 60
        if len(e): e = e[e.ts >= cut]
        if len(a): a = a[pd.to_datetime(a.created, utc=True) >= pd.Timestamp.now(tz="UTC") - pd.Timedelta(minutes=mins)]
    if sev and len(a): a = a[a.severity.isin(sev)]
    n = lambda df, col, val: int((df[col] == val).sum()) if len(df) else 0
    rs = r.status[0] if len(r) else "None yet"
    cards = [("Monitored files", files, "in test workspace", "#22d3ee"), ("Events observed", len(e), f"{int(e.simulated.sum()) if len(e) else 0} simulated", "#818cf8"),
             ("Suspicious alerts", len(a), "rule-based detections", "#fb923c"), ("Critical alerts", n(a, "severity", "Critical"), "score ≥ 75", "#f43f5e"),
             ("Open incidents", int((i.status != "Closed").sum()) if len(i) else 0, f"{int(i.contained.sum()) if len(i) else 0} contained (simulated)", "#c084fc"),
             ("Recovery check", rs, "SHA-256 verified" if rs == "VERIFIED" else "latest result", "#34d399" if rs == "VERIFIED" else "#94a3b8")]
    for col, cd in zip(st.columns(6), cards): col.markdown(kpi(*cd), unsafe_allow_html=True)
    st.write("")
    if a.empty and e.empty:
        st.markdown('<div class="empty"><b>No activity recorded yet.</b><br>Open <b>🧪 Workspace &amp; Demo</b> → Initialize → press <b>🚀 Start Guided Demo</b> to fill this dashboard with real, database-backed results.</div>', unsafe_allow_html=True); return
    c1, c2, c3 = st.columns([1.6, 1, 1])
    with c1.container(border=True):
        if len(e):
            e = e.assign(time=pd.to_datetime(e.ts, unit="s"))
            st.plotly_chart(style(px.histogram(e, x="time", color="type", nbins=40, title="File activity over time", color_discrete_sequence=["#22d3ee", "#818cf8", "#f43f5e", "#facc15"])), use_container_width=True)
        else: st.caption("No events in range.")
    with c2.container(border=True):
        if len(a): st.plotly_chart(style(px.pie(a, names="severity", hole=.62, title="Alert severity", color="severity", color_discrete_map=SEV)), use_container_width=True)
        else: st.caption("No alerts in range.")
    with c3.container(border=True):
        sc = int(a.sort_values("created").score.iloc[-1]) if len(a) else 0
        g = go.Figure(go.Indicator(mode="gauge+number", value=sc, title={"text": "Latest risk score"}, gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#e2e8f0"},
             "steps": [{"range": [0, 25], "color": "#0e7490"}, {"range": [25, 50], "color": "#a16207"}, {"range": [50, 75], "color": "#c2410c"}, {"range": [75, 100], "color": "#be123c"}]}))
        st.plotly_chart(style(g), use_container_width=True)
    d1, d2 = st.columns(2)
    with d1.container(border=True):
        if len(i): st.plotly_chart(style(px.pie(i, names="status", hole=.62, title="Incident status", color_discrete_sequence=["#c084fc", "#22d3ee", "#34d399"])), use_container_width=True)
    with d2.container(border=True):
        if len(a): st.plotly_chart(style(px.bar(a.category.value_counts().reset_index(), x="count", y="category", orientation="h", title="Detection categories", color_discrete_sequence=["#818cf8"])), use_container_width=True)
    l, rr = st.columns([1.4, 1])
    with l.container(border=True):
        st.markdown("#### 🚨 Recent alerts")
        if len(a):
            rows = "".join(f"<tr><td>{H.escape(x.id)}</td><td>{badge(x.severity, SEV[x.severity])}</td><td>{H.escape(x.category)}{' · ' + badge('SIM', '#94a3b8') if x.simulated else ''}</td><td>{x.score}</td><td>{x.files}</td><td>{H.escape(x.status)}</td></tr>" for x in a.sort_values("created", ascending=False).head(8).itertuples())
            st.markdown(f'<table class="tbl"><tr><th>ID</th><th>Severity</th><th>Category</th><th>Risk</th><th>Files</th><th>Status</th></tr>{rows}</table>', unsafe_allow_html=True)
        else: st.caption("No alerts in range.")
    with rr.container(border=True):
        st.markdown("#### 🕵️ Latest incidents &amp; next action")
        for x in i.sort_values("created", ascending=False).head(3).itertuples():
            st.markdown(f'<div class="icard" style="--c:{SEV[x.severity]}"><b>{H.escape(x.id)}</b> {badge(x.severity, SEV[x.severity])} {badge("CONTAINED (sim)", "#34d399") if x.contained else ""}<br>{H.escape(x.title)}<div class="next">➜ {nxt(x)}</div></div>', unsafe_allow_html=True)
        if i.empty: st.caption("No incidents yet.")
    with st.container(border=True):
        st.markdown("#### 📡 Live event feed")
        for x in e.sort_values("ts", ascending=False).head(8).itertuples():
            st.markdown(f'<div class="feed">{time.strftime("%H:%M:%S", time.localtime(x.ts))} · {x.type.upper()} · {H.escape(str(x.path))}{" → " + H.escape(str(x.dest)) if x.dest else ""}{" · [SIMULATED]" if x.simulated else ""}</div>', unsafe_allow_html=True)
    st.caption("Figures come from the SQLite database. Simulated records are harmless demo activity, not real attacks. Rule-based detection can miss attacks and raise false positives.")
