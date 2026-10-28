"""Explainable rule-based detection. NOT machine learning; scores are not probabilities."""
from .mitre import for_rule
DEFAULTS = {"window": 10.0, "mod_burst": 10, "rename_burst": 5, "ext_change": 5, "delete_burst": 5}
SEVERITY = [(75, "Critical"), (50, "High"), (25, "Medium"), (0, "Low")]
ACTIONS = {"Critical": "Contain the workspace, then restore from a verified clean backup.",
           "High": "Investigate and consider containment; verify backups.",
           "Medium": "Review the evidence and check file integrity.",
           "Low": "Monitor; likely benign (false positives are possible)."}

def severity(score: int) -> str:
    return next(n for t, n in SEVERITY if score >= t)

def _max_burst(times: list[float], window: float) -> int:
    times, best, j = sorted(times), 0, 0
    for i, t in enumerate(times):
        while t - times[j] > window: j += 1
        best = max(best, i - j + 1)
    return best

def detect(events: list[dict], cfg: dict | None = None) -> dict | None:
    """Evaluate one batch of events. Returns a detection dict or None."""
    cfg = {**DEFAULTS, **(cfg or {})}; w = cfg["window"]
    by = lambda t: [e for e in events if e["type"] == t]
    mods, mv, dels = by("modified"), by("moved"), by("deleted")
    ext = [e for e in mv if e.get("dest") and e["path"].rsplit(".", 1)[-1] != e["dest"].rsplit(".", 1)[-1]]
    rules = []
    for name, evs, th, base in [("Rapid modification burst", mods, cfg["mod_burst"], 30),
                                ("Mass rename activity", mv, cfg["rename_burst"], 30),
                                ("Suspicious extension changes", ext, cfg["ext_change"], 20),
                                ("Mass deletion pattern", dels, cfg["delete_burst"], 25)]:
        n = _max_burst([e["ts"] for e in evs], w)
        if n >= th:
            pts = min(base + 2 * (int(n) - int(th)), base + 20)
            rules.append({"rule": name, "count": n, "threshold": th, "window_s": w, "points": pts, "mitre_attack": for_rule(name)})
    if not rules: return None
    score = sum(r["points"] for r in rules)
    if len(rules) >= 2: score += 20; rules.append({"rule": "Combined activity score", "count": len(rules), "threshold": 2, "window_s": w, "points": 20})
    score = max(0, min(100, score)); sev = severity(score)
    files = len({e["path"] for e in events if e["type"] != "created"})
    cat = "Combined activity" if len(rules) > 2 else rules[0]["rule"]
    return {"category": cat, "score": score, "severity": sev, "files": files, "window": w, "rules": rules,
            "reason": "; ".join(f"{r['rule']}: {r['count']} >= {r['threshold']} in {w:g}s (+{r['points']})" for r in rules),
            "recommendation": ACTIONS[sev], "simulated": int(any(e.get("simulated") for e in events))}
