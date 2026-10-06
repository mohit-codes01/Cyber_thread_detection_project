"""
Indicator-Based Threat Detection Rules
Cross-references event attributes with threat intelligence feeds, known indicators,
and domain entropy models.
"""

from typing import List, Dict, Any
import pandas as pd
from backend.app.utils.threat_intel import (
    KNOWN_MALICIOUS_IPS, KNOWN_MALICIOUS_DOMAINS,
    calculate_entropy, SUSPICIOUS_TLDS
)


def detect_indicator_threats(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Flags events containing known malicious IPs, domains, or suspicious URLs."""
    threats = []
    cols = {c.lower(): c for c in df.columns}

    src_ip_col = cols.get("source_ip") or cols.get("src_ip") or cols.get("ip")
    dst_ip_col = cols.get("destination_ip") or cols.get("dst_ip")
    domain_col = cols.get("domain") or cols.get("host") or cols.get("hostname")
    url_col = cols.get("url") or cols.get("uri") or cols.get("path")

    # 1. Match Malicious IPs
    for ip_c in [src_ip_col, dst_ip_col]:
        if ip_c and ip_c in df.columns:
            for ip, intel in KNOWN_MALICIOUS_IPS.items():
                matched = df[df[ip_c].astype(str) == ip]
                if not matched.empty:
                    score = 90.0 if intel["risk"] == "CRITICAL" else 75.0
                    threats.append({
                        "threat_type": "Malicious IP Indicator",
                        "rule_code": "INTEL_MALICIOUS_IP_MATCH",
                        "rule_score": score,
                        "source_ip": ip if ip_c == src_ip_col else None,
                        "destination_ip": ip if ip_c == dst_ip_col else None,
                        "evidence": {
                            "matched_ip": ip,
                            "threat_category": intel["category"],
                            "threat_source": intel["source"]
                        },
                        "explanation": f"Activity associated with known malicious IP {ip} ({intel['category']})."
                    })

    # 2. Match Domains & Detect DGA
    if domain_col and domain_col in df.columns:
        unique_domains = df[domain_col].dropna().astype(str).unique()
        for dom in unique_domains:
            clean_dom = dom.strip().lower()
            if not clean_dom or clean_dom in ["none", "nan", "localhost"]:
                continue

            if clean_dom in KNOWN_MALICIOUS_DOMAINS:
                intel = KNOWN_MALICIOUS_DOMAINS[clean_dom]
                threats.append({
                    "threat_type": "Suspicious Domain",
                    "rule_code": "INTEL_MALICIOUS_DOMAIN_MATCH",
                    "rule_score": 85.0,
                    "domain": clean_dom,
                    "evidence": {
                        "domain": clean_dom,
                        "category": intel["category"]
                    },
                    "explanation": f"DNS resolution or HTTP request directed to known malicious domain '{clean_dom}'."
                })
            else:
                # Entropy DGA check
                entropy = calculate_entropy(clean_dom)
                if entropy >= 3.8 and len(clean_dom) >= 12:
                    threats.append({
                        "threat_type": "DGA Botnet Domain",
                        "rule_code": "BEHAVIOR_HIGH_ENTROPY_DOMAIN",
                        "rule_score": 75.0,
                        "domain": clean_dom,
                        "evidence": {
                            "domain": clean_dom,
                            "entropy": entropy
                        },
                        "explanation": f"Domain '{clean_dom}' exhibits high entropy ({entropy}), characteristic of Domain Generation Algorithms (DGA)."
                    })

    # 3. Match Web Attack URLs
    if url_col and url_col in df.columns:
        urls = df[url_col].dropna().astype(str).unique()
        for u in urls:
            u_clean = u.strip()
            if any(k in u_clean.lower() for k in ["/etc/passwd", "../", "cmd.exe", "powershell", "union select", "eval("]):
                threats.append({
                    "threat_type": "Suspicious Web Request",
                    "rule_code": "WEB_SUSPICIOUS_PAYLOAD_URL",
                    "rule_score": 80.0,
                    "url": u_clean[:255],
                    "evidence": {
                        "url": u_clean
                    },
                    "explanation": f"URL contains web attack signature (Path traversal, command injection, or SQLi): {u_clean[:80]}..."
                })

    return threats
