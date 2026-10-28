# RansomShield — Ransomware Behaviour Detection & Recovery Simulator
Educational, defensive project. **It never encrypts or deletes files.** Simulations touch only generated sample files in an approved workspace; deletion is synthetic telemetry; renames are reversible; containment is simulated in-app.

Workflow: Monitor → Detect → Alert → Investigate → Contain → Recover → Verify → Report

## Run
```
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS/Linux
pip install -r requirements.txt
streamlit run app.py
pytest -q
```
## Demo flow
1. 🧪 Workspace & Demo → Initialize (default `data/workspace`) → Generate sample files.
2. 💾 Backup & Recovery → Create baseline backup.
3. Start monitoring (tick confirmation) → run a scenario (`combined`). Or press **Start Guided Demo** to run all 12 steps automatically.
4. 🚨 Alerts: see score, evidence, rules; change status (resolve needs a note). 🕵️ Incidents: note, simulate containment, close.
5. 💾 Restore & verify → scorecard (SHA-256 re-check). 📄 Reports → JSON/CSV.

## How it works
- **Detector** (`core/detector.py`): sliding-window rules (modification burst, mass rename, extension change, mass deletion, combined). Score = sum of rule points (+20 combined), capped 0–100; severity Low <25, Medium <50, High <75, Critical ≥75. Not ML, not a probability; false positives happen.
- **Correlation**: alerts within 120 s join the same open incident.
- **Backup**: copy + `manifest.json` with SHA-256; verified at creation. Restore verifies the backup first, copies via temp file + `os.replace`, removes only `.locked_sim` leftovers, then re-hashes. "VERIFIED" only if every hash matches.
- **Safety**: `core/validators.py` rejects root/system/home dirs, non-empty unmarked folders, traversal and symlink escapes.
- **DB**: SQLite (`data/ransomshield.db`): events, alerts, incidents, notes, snapshots, recoveries, audit.

## MITRE ATT&CK mapping
The **🧭 MITRE ATT&CK** page gives each contextual mapping's technique ID, name, tactic, official MITRE link, relation to the simulator, represented evidence and limitations. Matching techniques are also included with triggered detector rules and are visible in alert details and JSON incident reports.

Current contextual mappings:
- **T1565.001 — Stored Data Manipulation**: rapid modifications to generated sample files.
- **T1486 — Data Encrypted for Impact**: contextual ransomware-like mapping for simulated mass renames/extension changes. The project does **not** encrypt files.
- **T1485 — Data Destruction**: contextual mapping for synthetic deletion telemetry. The project does **not** delete sample files in this scenario.

These are educational analogies, not a claim that a technique was performed or that an alert confirms an attack. See each official MITRE page from within the application.

## Limitations
No auth (local single-user demo only); no PDF export; no pre-recovery snapshot; monitor events are drained when a page refreshes; behaviour-based detection ≠ enterprise protection; incident-alert linking is automatic only.
