"""
Master Threat Detection Engine
Orchestrates rule heuristics, threat intelligence matching, Isolation Forest anomaly
detection, and supervised ML classification, computing composite risk scores.
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Tuple
import pandas as pd
from backend.app.detectors.brute_force import detect_brute_force
from backend.app.detectors.network_rules import detect_network_threats
from backend.app.detectors.indicator_rules import detect_indicator_threats
from backend.app.detectors.privilege_rules import detect_privilege_anomalies
from backend.app.ml.anomaly_detector import AnomalyDetector
from backend.app.ml.classifier import ThreatClassifier
from backend.app.ml.risk_scorer import RiskScorer


class ThreatDetectionEngine:
    """End-to-end hybrid threat detection pipeline."""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        self.risk_scorer = RiskScorer()

    def analyze_dataset(self, df: pd.DataFrame) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Executes full defensive analysis across dataframe.
        Returns:
            threats: list of fully populated threat dictionaries
            summary: aggregate statistics and metadata
        """
        start_time = datetime.utcnow()
        record_count = len(df)
        raw_threat_candidates: List[Dict[str, Any]] = []

        # ----------------------------------------------------
        # 1. Rule-Based Heuristic Scanners
        # ----------------------------------------------------
        raw_threat_candidates.extend(detect_brute_force(df))
        raw_threat_candidates.extend(detect_network_threats(df))
        raw_threat_candidates.extend(detect_indicator_threats(df))
        raw_threat_candidates.extend(detect_privilege_anomalies(df))

        # ----------------------------------------------------
        # 2. Machine Learning Anomaly Detection (Isolation Forest)
        # ----------------------------------------------------
        is_anomaly, anomaly_scores, ml_explanations = self.anomaly_detector.fit_predict(df)
        detection_mode = "HYBRID (Rules + Unsupervised Isolation Forest)"

        # ----------------------------------------------------
        # 3. Supervised Model Inference (if UNSW-NB15 compatible)
        # ----------------------------------------------------
        has_supervised = self.classifier.can_predict(df)
        sup_preds, sup_probs = np_zeros = ([0] * record_count, [0.0] * record_count)
        if has_supervised:
            sup_preds, sup_probs = self.classifier.predict(df)
            detection_mode = "HYBRID (Rules + Isolation Forest + Supervised Random Forest)"

        # ----------------------------------------------------
        # 4. Integrate High-Scoring ML Anomalies into Candidates
        # ----------------------------------------------------
        cols = {c.lower(): c for c in df.columns}
        src_col = cols.get("source_ip") or cols.get("src_ip") or cols.get("ip")
        user_col = cols.get("username") or cols.get("user")
        action_col = cols.get("action") or cols.get("event_type")

        for idx in range(record_count):
            a_score = float(anomaly_scores[idx]) if idx < len(anomaly_scores) else 0.0
            s_score = float(sup_probs[idx]) * 100.0 if has_supervised else 0.0

            # If statistical anomaly is marked and score is high (>= 70)
            if (is_anomaly[idx] and a_score >= 70.0) or s_score >= 65.0:
                row = df.iloc[idx]
                src = str(row[src_col]) if src_col and pd.notna(row.get(src_col)) else "Unknown"
                usr = str(row[user_col]) if user_col and pd.notna(row.get(user_col)) else None
                act = str(row[action_col]) if action_col and pd.notna(row.get(action_col)) else "Network Flow"
                expl = ml_explanations[idx].get("summary", "Statistical deviation detected.")

                raw_threat_candidates.append({
                    "threat_type": "Statistical Behavioral Anomaly" if a_score >= s_score else "Network Attack Signature",
                    "rule_code": "ML_ISOLATION_FOREST" if a_score >= s_score else "ML_RANDOM_FOREST",
                    "rule_score": 0.0,
                    "anomaly_score": a_score,
                    "ml_score": s_score,
                    "indicator_score": 0.0,
                    "source_ip": src if src != "Unknown" else None,
                    "username": usr,
                    "event_name": act,
                    "evidence": {
                        "ml_mode": detection_mode,
                        "anomaly_score": round(a_score, 1),
                        "ml_confidence": round(s_score, 1),
                        "details": ml_explanations[idx]
                    },
                    "explanation": expl
                })

        # ----------------------------------------------------
        # 5. Composite Risk Scoring & Normalization
        # ----------------------------------------------------
        final_threats: List[Dict[str, Any]] = []
        for cand in raw_threat_candidates:
            r_score = float(cand.get("rule_score", 0.0))
            a_score = float(cand.get("anomaly_score", 0.0))
            m_score = float(cand.get("ml_score", 0.0))
            i_score = float(cand.get("indicator_score", 0.0))
            t_type = cand.get("threat_type", "Suspicious Activity")

            # Entity identification
            entity = cand.get("source_ip") or cand.get("username") or cand.get("domain") or "Target Asset"

            scored = self.risk_scorer.compute_risk(
                rule_score=r_score,
                anomaly_score=a_score,
                ml_score=m_score,
                indicator_score=i_score,
                threat_type=t_type,
                rule_name=cand.get("rule_code", ""),
                entity_name=str(entity)
            )

            evidence_val = cand.get("evidence")
            evidence_str = json.dumps(evidence_val) if isinstance(evidence_val, dict) else str(evidence_val or "{}")

            final_threats.append({
                "threat_type": t_type,
                "severity": scored["severity"],
                "risk_score": scored["risk_score"],
                "rule_score": scored["rule_score"],
                "anomaly_score": scored["anomaly_score"],
                "ml_score": scored["ml_score"],
                "indicator_score": scored["indicator_score"],
                "detection_method": "RULE" if r_score > 0 and a_score == 0 else ("ML_ANOMALY" if a_score > 0 and r_score == 0 else "HYBRID"),
                "confidence": 0.92 if scored["severity"] == "CRITICAL" else 0.85,
                "source_ip": cand.get("source_ip"),
                "destination_ip": cand.get("destination_ip"),
                "username": cand.get("username"),
                "domain": cand.get("domain"),
                "url": cand.get("url"),
                "event_name": cand.get("event_name"),
                "rule_triggered": cand.get("rule_code"),
                "explanation": cand.get("explanation") or scored["explanation"],
                "recommended_actions": scored["recommended_actions"],
                "evidence": evidence_str,
                "status": "OPEN",
                "timestamp": datetime.utcnow()
            })

        # Deduplicate threats by (threat_type, source_ip, username, rule_triggered)
        seen = set()
        deduped_threats = []
        for t in final_threats:
            key = (t["threat_type"], t.get("source_ip"), t.get("username"), t.get("rule_triggered"))
            if key not in seen:
                seen.add(key)
                deduped_threats.append(t)

        # Sort by risk score descending
        deduped_threats.sort(key=lambda x: x["risk_score"], reverse=True)

        # ----------------------------------------------------
        # 6. Aggregate Summary Statistics
        # ----------------------------------------------------
        duration = round((datetime.utcnow() - start_time).total_seconds(), 2)
        crit_count = sum(1 for t in deduped_threats if t["severity"] == "CRITICAL")
        high_count = sum(1 for t in deduped_threats if t["severity"] == "HIGH")
        med_count = sum(1 for t in deduped_threats if t["severity"] == "MEDIUM")
        low_count = sum(1 for t in deduped_threats if t["severity"] == "LOW")

        sec_eval = self.risk_scorer.calculate_environment_security_score(deduped_threats)

        summary = {
            "total_records": record_count,
            "normal_records": max(0, record_count - len(deduped_threats)),
            "threats_detected": len(deduped_threats),
            "critical_threats": crit_count,
            "high_threats": high_count,
            "medium_threats": med_count,
            "low_threats": low_count,
            "security_score": sec_eval["overall_score"],
            "security_grade": sec_eval["health_grade"],
            "risk_breakdown": sec_eval["breakdown"],
            "detection_mode": detection_mode,
            "duration_seconds": duration,
            "analyzed_at": datetime.utcnow().isoformat()
        }

        return deduped_threats, summary
