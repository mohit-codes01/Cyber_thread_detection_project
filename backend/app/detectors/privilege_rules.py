"""
Privilege & Account Anomaly Detection Rules
Detects unexpected privilege escalation, root/administrator role grants,
and repeated authorization violations.
"""

from typing import List, Dict, Any
import pandas as pd


def detect_privilege_anomalies(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Inspects actions and usernames for unauthorized privilege escalation attempts."""
    threats = []
    cols = {c.lower(): c for c in df.columns}

    action_col = cols.get("action") or cols.get("event_type") or cols.get("command")
    user_col = cols.get("username") or cols.get("user")
    status_col = cols.get("status") or cols.get("result")
    ip_col = cols.get("source_ip") or cols.get("src_ip")

    if not action_col:
        return threats

    # Check for sensitive privilege commands or role modification
    escalation_patterns = [
        "sudo", "su root", "privilege_elevation", "grant_admin",
        "chmod 777", "add_admin", "setuid", "disable_firewall",
        "mimikatz", "shadow_copy_delete", "net user /add"
    ]

    for _, row in df.iterrows():
        act_val = str(row.get(action_col, "")).lower()
        matched_kw = None
        for pattern in escalation_patterns:
            if pattern in act_val:
                matched_kw = pattern
                break

        if matched_kw:
            user = str(row.get(user_col, "Unknown")) if user_col else "Unknown"
            ip = str(row.get(ip_col, "Unknown")) if ip_col else "Unknown"
            status_val = str(row.get(status_col, "ATTEMPT")).upper() if status_col else "ATTEMPT"
            is_fail = any(f in status_val for f in ["FAIL", "DENIED", "REJECT"])

            threats.append({
                "threat_type": "Privilege Escalation Anomaly",
                "rule_code": "PRIV_SUSPICIOUS_COMMAND",
                "rule_score": 85.0 if not is_fail else 65.0,
                "username": user,
                "source_ip": ip,
                "evidence": {
                    "matched_action": act_val,
                    "keyword": matched_kw,
                    "status": status_val
                },
                "explanation": f"User '{user}' executed sensitive privilege operation '{matched_kw}' with status '{status_val}'."
            })

    return threats
