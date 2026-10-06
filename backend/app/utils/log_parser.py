"""
Log Parser & Schema Auto-Detection
Parses CSV, JSON, and text security logs, detects standard fields, and assesses data quality.
"""

import os
import json
import re
from typing import Dict, Any, List, Tuple
import pandas as pd
from backend.app.schemas.analysis import DataQualityReport

# Synonyms for standard security log fields
FIELD_CANDIDATES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "event_time", "start_time", "created_at"],
    "source_ip": ["src_ip", "srcip", "source_ip", "sourceip", "ip", "src_addr", "saddr", "client_ip"],
    "destination_ip": ["dst_ip", "dstip", "destination_ip", "dest_ip", "dst_addr", "daddr", "server_ip"],
    "port": ["port", "dst_port", "destination_port", "dport", "service_port", "target_port"],
    "protocol": ["proto", "protocol", "transport", "net_proto"],
    "username": ["username", "user", "user_name", "account", "login_user", "principal", "target_user"],
    "event_type": ["event_type", "type", "category", "attack_cat", "activity", "log_name"],
    "action": ["action", "operation", "command", "method", "event"],
    "status": ["status", "result", "state", "outcome", "response_code", "label"],
    "bytes_sent": ["bytes_sent", "sbytes", "bytes_out", "out_bytes", "sent_bytes"],
    "bytes_received": ["bytes_received", "dbytes", "bytes_in", "in_bytes", "recv_bytes"]
}


def parse_dataset(file_path: str) -> pd.DataFrame:
    """Safely loads CSV, JSON, or log files into a pandas DataFrame."""
    ext = os.path.splitext(file_path)[1].lower()

    try:
        if ext == ".csv":
            df = pd.read_csv(file_path, low_memory=False)
        elif ext == ".json":
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                df = pd.DataFrame(data)
            elif isinstance(data, dict):
                # If wrapped in a results/events key
                for key in ["events", "logs", "records", "data"]:
                    if key in data and isinstance(data[key], list):
                        df = pd.DataFrame(data[key])
                        break
                else:
                    df = pd.DataFrame([data])
            else:
                df = pd.DataFrame()
        else:
            # Fallback for text/syslog files: simple line parsing
            records = []
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Try simple regex extraction for IP and messages
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    records.append({
                        "raw_log": line,
                        "source_ip": ip_match.group(0) if ip_match else "127.0.0.1",
                        "status": "FAILURE" if "fail" in line.lower() else "SUCCESS"
                    })
            df = pd.DataFrame(records)

        return df

    except Exception as e:
        raise ValueError(f"Failed to parse security dataset: {str(e)}")


def detect_field_mapping(columns: List[str]) -> Dict[str, str]:
    """Auto-detects canonical security schema fields from arbitrary column names."""
    mapping = {}
    lower_cols = {c.lower(): c for c in columns}

    for standard_field, candidates in FIELD_CANDIDATES.items():
        for cand in candidates:
            if cand in lower_cols:
                mapping[standard_field] = lower_cols[cand]
                break

    return mapping


def analyze_data_quality(df: pd.DataFrame, filename: str, file_size: int) -> DataQualityReport:
    """Generates an objective data quality assessment and field mapping."""
    record_count = len(df)
    columns = list(df.columns)
    column_count = len(columns)

    missing_dict = {}
    total_cells = max(record_count * column_count, 1)
    missing_cells = 0

    for col in columns:
        m_count = int(df[col].isnull().sum())
        missing_dict[col] = m_count
        missing_cells += m_count

    # Quality score: penalty for missing values and lack of standard security fields
    detected_fields = detect_field_mapping(columns)
    missing_ratio = missing_cells / total_cells
    standard_field_coverage = len(detected_fields) / len(FIELD_CANDIDATES)

    quality_score = max(5.0, min(100.0, (1.0 - missing_ratio * 0.5) * (0.5 + 0.5 * standard_field_coverage) * 100))

    # Sample preview (up to 5 records, sanitized of non-serializable objects)
    sample_preview = []
    if record_count > 0:
        preview_df = df.head(5).fillna("")
        sample_preview = preview_df.to_dict(orient="records")

    return DataQualityReport(
        filename=filename,
        file_size=file_size,
        record_count=record_count,
        column_count=column_count,
        columns=columns,
        detected_fields=detected_fields,
        missing_values=missing_dict,
        quality_score=round(quality_score, 1),
        sample_preview=sample_preview
    )
