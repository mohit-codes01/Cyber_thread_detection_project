"""
Threat Intelligence Utilities & Indicator Analysis
Provides offline defensive threat evaluation, Shannon entropy DGA detection,
IP/Domain/URL heuristics, and optional external threat intel integration.
"""

import math
import ipaddress
import re
from typing import Dict, Any, List, Optional
import requests
from backend.app.config import settings

# Curated local defensive indicators database for offline evaluation & demo
KNOWN_MALICIOUS_IPS = {
    "185.220.101.5": {"category": "Tor Exit Node / Scanner", "risk": "HIGH", "source": "AbuseIPDB Feed"},
    "45.33.32.156": {"category": "Brute Force Scanner", "risk": "HIGH", "source": "Internal SOC"},
    "194.26.29.112": {"category": "Cobalt Strike C2", "risk": "CRITICAL", "source": "Emerging Threats"},
    "103.203.57.18": {"category": "Credential Stuffing Source", "risk": "HIGH", "source": "Internal SOC"},
    "91.240.118.172": {"category": "Mirai Botnet Scanner", "risk": "CRITICAL", "source": "Threat Fox"},
    "198.51.100.23": {"category": "Simulated Malicious C2", "risk": "CRITICAL", "source": "Synthetic Demo"}
}

KNOWN_MALICIOUS_DOMAINS = {
    "evil-update-service.cc": {"category": "C2 Server", "risk": "CRITICAL"},
    "login-verify-account.tk": {"category": "Phishing / Credential Harvester", "risk": "HIGH"},
    "payload-delivery-cdn.ru": {"category": "Malware Dropper", "risk": "CRITICAL"},
    "x92-malicious-c2.top": {"category": "DGA Botnet Node", "risk": "CRITICAL"},
    "secure-banking-auth.xyz": {"category": "Phishing Domain", "risk": "HIGH"}
}

SUSPICIOUS_TLDS = {".top", ".xyz", ".cc", ".tk", ".work", ".click", ".buzz", ".ru", ".cf"}

KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"name": "Empty File Probe", "risk": "LOW"},
    "44d88612fea8a8f36de82e1278abb02f": {"name": "EICAR Standard Antivirus Test File (MD5)", "risk": "HIGH"},
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"name": "EICAR Test File (SHA-256)", "risk": "HIGH"},
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {"name": "Known Password Sample Hash", "risk": "MEDIUM"}
}


def calculate_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string (useful for DGA domain detection)."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in freq.values():
        prob = count / text_len
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address belongs to RFC 1918 private / loopback ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def analyze_ip_indicator(ip: str) -> Dict[str, Any]:
    """Analyzes an IP address using validation, RFC checks, and threat intel matching."""
    ip = ip.strip()
    is_valid = False
    is_private = False
    try:
        ip_obj = ipaddress.ip_address(ip)
        is_valid = True
        is_private = ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return {
            "indicator_type": "IP",
            "value": ip,
            "is_suspicious": False,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "category": "Invalid IP Format",
            "details": {"error": "Invalid IPv4 or IPv6 address string."},
            "recommendations": ["Verify the IP format in your logs or configuration."]
        }

    # Check local intel list
    if ip in KNOWN_MALICIOUS_IPS:
        intel = KNOWN_MALICIOUS_IPS[ip]
        score = 90.0 if intel["risk"] == "CRITICAL" else 75.0
        return {
            "indicator_type": "IP",
            "value": ip,
            "is_suspicious": True,
            "risk_score": score,
            "risk_level": intel["risk"],
            "category": intel["category"],
            "details": {
                "ip_type": "Private" if is_private else "Public",
                "known_source": intel["source"],
                "reputation": "Known Malicious Actor"
            },
            "recommendations": [
                f"Block inbound/outbound communication to {ip} at the perimeter firewall.",
                "Review security event logs for prior connections from this IP.",
                "Isolate any internal systems that established bidirectional TCP sessions with this IP."
            ]
        }

    # Optional external query if key exists
    if settings.THREAT_INTEL_API_KEY and not is_private:
        # Template for real API lookup
        pass

    # Baseline risk for clean/internal IP
    base_score = 10.0 if not is_private else 5.0
    return {
        "indicator_type": "IP",
        "value": ip,
        "is_suspicious": False,
        "risk_score": base_score,
        "risk_level": "LOW",
        "category": "Private Network" if is_private else "Public IP (No Known Threat)",
        "details": {
            "ip_type": "Private/Internal" if is_private else "Public",
            "threat_intel_match": False
        },
        "recommendations": [
            "No immediate defensive blocking required.",
            "Continue standard monitoring in access logs."
        ]
    }


def analyze_domain_indicator(domain: str) -> Dict[str, Any]:
    """Analyzes a domain for entropy (DGA), suspicious TLDs, and known bad domains."""
    domain = domain.strip().lower()
    entropy = calculate_entropy(domain)
    
    # Check known malicious
    if domain in KNOWN_MALICIOUS_DOMAINS:
        intel = KNOWN_MALICIOUS_DOMAINS[domain]
        return {
            "indicator_type": "DOMAIN",
            "value": domain,
            "is_suspicious": True,
            "risk_score": 88.0,
            "risk_level": intel["risk"],
            "category": intel["category"],
            "details": {
                "entropy": entropy,
                "reputation": "Identified in Threat Intel Blacklist"
            },
            "recommendations": [
                f"Sinkhole or blacklist DNS queries for {domain} across internal resolvers.",
                "Audit internal DNS logs to identify workstations requesting this domain."
            ]
        }

    # Heuristic checks: High entropy (> 3.8) suggests DGA (Domain Generation Algorithm)
    is_suspicious = False
    risk_score = 15.0
    reasons = []

    if entropy > 3.8 and len(domain) > 12:
        is_suspicious = True
        risk_score += 45.0
        reasons.append(f"High Shannon entropy ({entropy}), indicative of algorithmic generation (DGA).")

    # Check suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            is_suspicious = True
            risk_score += 25.0
            reasons.append(f"Uses high-risk Top-Level Domain ({tld}).")
            break

    risk_score = min(95.0, risk_score)
    risk_level = "CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    return {
        "indicator_type": "DOMAIN",
        "value": domain,
        "is_suspicious": is_suspicious,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category": "Suspicious DGA Domain" if is_suspicious else "Standard Domain",
        "details": {
            "entropy": entropy,
            "length": len(domain),
            "flags": reasons
        },
        "recommendations": [
            "Inspect DNS resolution history for internal endpoints.",
            "Verify SSL/TLS certificate validity and issuing authority."
        ] if is_suspicious else ["Domain appears normal. Standard monitoring advised."]
    }


def analyze_url_indicator(url: str) -> Dict[str, Any]:
    """Inspects a URL for malicious patterns (SQLi, path traversal, shell commands, obfuscation)."""
    url = url.strip()
    patterns = [
        (r'(\b(select|union|insert|delete|drop|benchmark|sleep)\b)', "SQL Injection pattern detected"),
        (r'(\.\./|\.\.\\|/etc/passwd|windows/system32)', "Path Traversal pattern detected"),
        (r'(<script|javascript:|alert\(|onload=)', "Cross-Site Scripting (XSS) payload detected"),
        (r'(\b(eval|base64_decode|system|exec|passthru|powershell|cmd\.exe)\b)', "Remote Code Execution / Shell pattern detected")
    ]

    detected = []
    for regex, desc in patterns:
        if re.search(regex, url, re.IGNORECASE):
            detected.append(desc)

    is_suspicious = len(detected) > 0
    risk_score = min(95.0, 30.0 + len(detected) * 30.0) if is_suspicious else 10.0
    risk_level = "CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else "LOW")

    return {
        "indicator_type": "URL",
        "value": url,
        "is_suspicious": is_suspicious,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "category": "Web Application Attack" if is_suspicious else "Legitimate URL",
        "details": {
            "url_length": len(url),
            "signatures_matched": detected
        },
        "recommendations": [
            "Block request on Web Application Firewall (WAF).",
            "Sanitize input parameters and enforce parameterized SQL queries.",
            "Inspect server access logs for similar HTTP requests from the source IP."
        ] if is_suspicious else ["URL exhibits no dangerous pattern signatures."]
    }


def analyze_hash_indicator(file_hash: str) -> Dict[str, Any]:
    """Analyzes a file hash (MD5, SHA-1, SHA-256) against the known indicator database."""
    file_hash = file_hash.strip().lower()
    hash_len = len(file_hash)
    hash_type = "MD5" if hash_len == 32 else ("SHA-1" if hash_len == 40 else ("SHA-256" if hash_len == 64 else "UNKNOWN"))

    if file_hash in KNOWN_MALICIOUS_HASHES:
        match = KNOWN_MALICIOUS_HASHES[file_hash]
        score = 85.0 if match["risk"] == "HIGH" else 50.0
        return {
            "indicator_type": "HASH",
            "value": file_hash,
            "is_suspicious": True,
            "risk_score": score,
            "risk_level": match["risk"],
            "category": match["name"],
            "details": {
                "algorithm": hash_type,
                "reputation": "Known Malicious File / Indicator"
            },
            "recommendations": [
                "Quarantine or remove the file from all affected endpoints immediately.",
                "Execute an endpoint detection and response (EDR) scan across your fleet.",
                "Review process execution logs for parent processes that spawned this binary."
            ]
        }

    return {
        "indicator_type": "HASH",
        "value": file_hash,
        "is_suspicious": False,
        "risk_score": 10.0,
        "risk_level": "LOW",
        "category": "Unknown / Unclassified Hash",
        "details": {
            "algorithm": hash_type,
            "reputation": "No matching malicious hash signature found."
        },
        "recommendations": [
            "Note that hashes are unique signatures; zero matches does not guarantee safety.",
            "Perform dynamic behavioral or sandbox analysis if the binary is untrusted."
        ]
    }
