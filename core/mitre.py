"""Curated MITRE ATT&CK references for RansomShield's simulated behaviours.

These are contextual mappings, not claims that the simulator performs the
ATT&CK techniques or that a detected event proves malicious activity.
"""

ATTACK_URL = "https://attack.mitre.org/"

TECHNIQUES = {
    "T1565.001": {
        "id": "T1565.001",
        "name": "Stored Data Manipulation",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1565/001/",
        "description": "An adversary manipulates data stored on a system to affect its integrity.",
        "project_relation": "The rapid-modification simulation appends a harmless marker to generated sample files. This is a controlled analogue of suspicious stored-data changes.",
        "evidence": "A burst of file-modification events within the configured time window.",
        "caveat": "Normal bulk edits can also trigger this rule; file changes alone do not establish malicious intent.",
    },
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "description": "Adversaries may encrypt data to interrupt access to it, a behaviour commonly associated with ransomware.",
        "project_relation": "Mass renaming and changing extensions are used as visible ransomware-like indicators in the simulator. RansomShield does not encrypt files.",
        "evidence": "A burst of rename events and/or file-extension changes in the monitored test workspace.",
        "caveat": "Renaming or changing an extension is not the same as encryption and is not proof that T1486 occurred.",
    },
    "T1485": {
        "id": "T1485",
        "name": "Data Destruction",
        "tactic": "Impact",
        "url": "https://attack.mitre.org/techniques/T1485/",
        "description": "Adversaries may destroy data to interrupt availability or cause operational impact.",
        "project_relation": "The mass-deletion scenario emits synthetic deletion telemetry only; it does not delete the sample files.",
        "evidence": "A burst of simulated deletion events in the configured time window.",
        "caveat": "Because deletion is synthetic in this project, the alert demonstrates detection logic rather than an actual destructive action.",
    },
}

RULE_MAPPING = {
    "Rapid modification burst": ["T1565.001"],
    "Mass rename activity": ["T1486"],
    "Suspicious extension changes": ["T1486"],
    "Mass deletion pattern": ["T1485"],
}


def for_rule(rule_name: str) -> list[dict]:
    """Return ATT&CK records associated with a detector rule."""
    return [TECHNIQUES[tid].copy() for tid in RULE_MAPPING.get(rule_name, [])]
