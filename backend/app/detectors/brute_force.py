"""
Brute Force & Authentication Anomaly Detection Rule
Flags repeated authentication failures, credential stuffing, and dictionary attacks.
"""

from typing import List, Dict, Any
import pandas as pd


def detect_brute_force(df: pd.DataFrame, threshold: int = 4) -> List[Dict[str, Any]]:
    """
    Scans events for authentication failure spikes by source IP or username.
    Returns list of detected threat records.
    """
    threats = []
    
    # Identify relevant columns
    cols = {c.lower(): c for c in df.columns}
    ip_col = cols.get("source_ip") or cols.get("src_ip") or cols.get("ip") or cols.get("saddr")
    user_col = cols.get("username") or cols.get("user") or cols.get("account")
    status_col = cols.get("status") or cols.get("action") or cols.get("result")

    if not status_col or (not ip_col and not user_col):
        return threats

    # Filter for failure statuses
    fail_mask = df[status_col].astype(str).str.upper().str.contains(r'FAIL|DENIED|REJECT|ERROR|ATTEMPT|401|403', regex=True)
    failures = df[fail_mask]

    if failures.empty:
        return threats

    # Check grouped by source IP
    if ip_col:
        ip_counts = failures[ip_col].value_counts()
        for ip, count in ip_counts.items():
            if pd.isna(ip) or str(ip).strip() in ["", "nan", "None"]:
                continue
            if count >= threshold:
                threats.append({
                    "threat_type": "Brute Force Authentication",
                    "rule_code": "AUTH_BRUTE_FORCE_IP",
                    "rule_score": min(100.0, 50.0 + count * 5.0),
                    "source_ip": str(ip),
                    "username": str(failures[failures[ip_col] == ip][user_col].iloc[0]) if user_col else None,
                    "evidence": {
                        "failed_attempts": int(count),
                        "threshold": threshold,
                        "trigger": f"Detected {count} consecutive authentication failures from IP {ip}."
                    },
                    "explanation": f"Detected {count} authentication failures originating from source IP {ip}, exceeding threshold of {threshold}."
                })

    # Check grouped by target username (credential stuffing / targeted account attack)
    if user_col:
        user_counts = failures[user_col].value_counts()
        for user, count in user_counts.items():
            if pd.isna(user) or str(user).strip() in ["", "nan", "None", "anonymous"]:
                continue
            if count >= threshold:
                # Avoid exact duplicate threat if already flagged by IP
                existing = [t for t in threats if t.get("username") == str(user)]
                if not existing:
                    threats.append({
                        "threat_type": "Credential Stuffing Attack",
                        "rule_code": "AUTH_CREDENTIAL_STUFFING_USER",
                        "rule_score": min(95.0, 45.0 + count * 5.0),
                        "username": str(user),
                        "source_ip": str(failures[failures[user_col] == user][ip_col].iloc[0]) if ip_col else None,
                        "evidence": {
                            "targeted_user": str(user),
                            "failed_attempts": int(count)
                        },
                        "explanation": f"Account '{user}' subjected to {count} rapid failed logins, indicating potential password spray or dictionary attack."
                    })

    return threats
