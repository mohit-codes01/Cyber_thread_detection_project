"""
Network Threat & Anomaly Detection Rules
Identifies port scanning sweeps, connections to known trojan/backdoor ports,
and anomalous high-volume outbound data exfiltration.
"""

from typing import List, Dict, Any
import pandas as pd

KNOWN_SUSPICIOUS_PORTS = {
    4444: "Metasploit Default Listener / Reverse Shell",
    1337: "Common Hacker / Backdoor Port",
    31337: "Back Orifice Trojan",
    6667: "IRC Channel / Legacy Botnet C2",
    8888: "Alternative HTTP / Web Proxy / Common C2",
    5555: "Android ADB Debug Bridge (Unauthenticated)",
    23: "Telnet (Unencrypted / Brute-force vector)",
    3389: "RDP Exposure / Remote Desktop Attack",
}


def detect_network_threats(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Evaluates network flow records for port scans, dangerous ports, and exfiltration."""
    threats = []
    cols = {c.lower(): c for c in df.columns}

    ip_col = cols.get("source_ip") or cols.get("src_ip") or cols.get("saddr")
    dst_ip_col = cols.get("destination_ip") or cols.get("dst_ip") or cols.get("daddr")
    port_col = cols.get("port") or cols.get("dst_port") or cols.get("dport")
    bytes_col = cols.get("bytes_sent") or cols.get("sbytes") or cols.get("bytes")

    # 1. Port Scan Detection: Single Source IP probing > 5 distinct ports
    if ip_col and port_col:
        try:
            valid_ports = df.dropna(subset=[ip_col, port_col])
            port_counts = valid_ports.groupby(ip_col)[port_col].nunique()
            for src_ip, unique_ports in port_counts.items():
                if unique_ports >= 5:
                    threats.append({
                        "threat_type": "Network Port Scanning",
                        "rule_code": "NET_PORT_SCAN_RECON",
                        "rule_score": min(95.0, 55.0 + unique_ports * 3.0),
                        "source_ip": str(src_ip),
                        "destination_ip": str(valid_ports[valid_ports[ip_col] == src_ip][dst_ip_col].iloc[0]) if dst_ip_col else None,
                        "evidence": {
                            "distinct_ports_targeted": int(unique_ports),
                            "scanner_ip": str(src_ip)
                        },
                        "explanation": f"Source IP {src_ip} probed {unique_ports} distinct destination ports in rapid succession (Reconnaissance pattern)."
                    })
        except Exception:
            pass

    # 2. Suspicious / Backdoor Ports Detection
    if port_col:
        try:
            # Convert port to numeric
            ports_series = pd.to_numeric(df[port_col], errors='coerce')
            for bad_port, desc in KNOWN_SUSPICIOUS_PORTS.items():
                matched = df[ports_series == bad_port]
                if not matched.empty:
                    for _, row in matched.head(3).iterrows():
                        src = str(row[ip_col]) if ip_col and pd.notna(row.get(ip_col)) else "Unknown"
                        dst = str(row[dst_ip_col]) if dst_ip_col and pd.notna(row.get(dst_ip_col)) else "Unknown"
                        threats.append({
                            "threat_type": "Suspicious Port Activity",
                            "rule_code": f"NET_SUSPICIOUS_PORT_{bad_port}",
                            "rule_score": 75.0,
                            "source_ip": src,
                            "destination_ip": dst,
                            "evidence": {
                                "port": bad_port,
                                "description": desc
                            },
                            "explanation": f"Network session established on high-risk port {bad_port} ({desc})."
                        })
        except Exception:
            pass

    # 3. Data Exfiltration Detection: Unusually large bytes_sent (e.g. > 10MB or > 3 sigma)
    if bytes_col and ip_col:
        try:
            bytes_series = pd.to_numeric(df[bytes_col], errors='coerce').fillna(0)
            exfil_threshold = 10 * 1024 * 1024  # 10 MB in bytes
            large_flows = df[bytes_series > exfil_threshold]

            for _, row in large_flows.head(3).iterrows():
                vol_mb = round(float(row[bytes_col]) / (1024 * 1024), 2)
                src = str(row[ip_col]) if pd.notna(row.get(ip_col)) else "Internal Host"
                dst = str(row[dst_ip_col]) if dst_ip_col and pd.notna(row.get(dst_ip_col)) else "External Host"
                threats.append({
                    "threat_type": "Data Exfiltration Indicator",
                    "rule_code": "NET_DATA_EXFILTRATION_VOLUME",
                    "rule_score": min(95.0, 70.0 + vol_mb * 0.5),
                    "source_ip": src,
                    "destination_ip": dst,
                    "evidence": {
                        "bytes_transferred": float(row[bytes_col]),
                        "volume_mb": vol_mb
                    },
                    "explanation": f"Abnormally high outbound payload ({vol_mb} MB) transferred from {src} to {dst}."
                })
        except Exception:
            pass

    return threats
