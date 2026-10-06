"""
Composite Risk Scoring Engine & Explainability Module
Synthesizes Rule, Anomaly, ML, and Indicator signals into a normalized 0-100 score,
assigns severity bands, and computes overall environment security posture.
"""

from typing import Dict, Any, List, Tuple
from backend.app.config import settings


class RiskScorer:
    """Combines multi-modal defensive security signals into an explainable risk score."""

    def __init__(
        self,
        weight_rule: float = settings.WEIGHT_RULE,
        weight_anomaly: float = settings.WEIGHT_ANOMALY,
        weight_ml: float = settings.WEIGHT_ML,
        weight_indicator: float = settings.WEIGHT_INDICATOR
    ):
        self.w_rule = weight_rule
        self.w_anomaly = weight_anomaly
        self.w_ml = weight_ml
        self.w_indicator = weight_indicator

    def compute_risk(
        self,
        rule_score: float,
        anomaly_score: float,
        ml_score: float,
        indicator_score: float,
        threat_type: str,
        rule_name: str = "",
        entity_name: str = ""
    ) -> Dict[str, Any]:
        """
        Calculates final composite risk score (0-100), severity level,
        rationale explanation, and defensive next steps.
        """
        # Linear weighted combination
        composite = (
            self.w_rule * rule_score +
            self.w_anomaly * anomaly_score +
            self.w_ml * ml_score +
            self.w_indicator * indicator_score
        )

        # Non-linear boost: If high rule OR critical indicator matches, ensure score reflects urgency
        if rule_score >= 80.0 or indicator_score >= 80.0:
            composite = max(composite, max(rule_score, indicator_score) * 0.9)

        final_score = round(min(100.0, max(0.0, composite)), 1)

        # Categorize Severity Band
        if final_score >= 75.0:
            severity = "CRITICAL"
        elif final_score >= 50.0:
            severity = "HIGH"
        elif final_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Construct Transparent Rationale ("Why was this flagged?")
        reasons = []
        if rule_score > 0:
            reasons.append(f"Deterministic Rule [{rule_name or threat_type}] triggered (score: {rule_score:.0f})")
        if indicator_score > 0:
            reasons.append(f"Threat Intelligence indicator match (score: {indicator_score:.0f})")
        if anomaly_score >= 50.0:
            reasons.append(f"Isolation Forest detected statistical outlier behavior (anomaly index: {anomaly_score:.1f})")
        if ml_score >= 50.0:
            reasons.append(f"Supervised ML classifier flagged attack pattern (confidence: {ml_score:.1f}%)")

        explanation = "; ".join(reasons) if reasons else "Event exhibits baseline activity with minor deviation."

        # Construct Defensive Recommendations ("Recommended Next Steps")
        recommendations = self._generate_defensive_actions(threat_type, severity, entity_name)

        return {
            "risk_score": final_score,
            "severity": severity,
            "rule_score": round(rule_score, 1),
            "anomaly_score": round(anomaly_score, 1),
            "ml_score": round(ml_score, 1),
            "indicator_score": round(indicator_score, 1),
            "explanation": explanation,
            "recommended_actions": recommendations
        }

    def _generate_defensive_actions(self, threat_type: str, severity: str, entity: str) -> str:
        """Generates context-aware, safe defensive suggestions."""
        t_type = threat_type.lower()
        steps = []

        if "brute" in t_type or "auth" in t_type or "login" in t_type:
            steps.extend([
                f"Temporarily lock or enforce MFA verification for targeted account ({entity or 'user'}).",
                "Verify authentication logs to check if password guessing was successful.",
                "Throttle repeated authentication requests from the source IP address."
            ])
        elif "port" in t_type or "scan" in t_type or "recon" in t_type:
            steps.extend([
                "Block the scanning IP at the perimeter boundary firewall.",
                "Verify that internal ports exposed to the scanner are secured and patched.",
                "Review firewall rejection and dropped connection rate."
            ])
        elif "exfiltration" in t_type or "traffic" in t_type or "data" in t_type:
            steps.extend([
                "Isolate the originating host from the internal subnet pending forensic review.",
                "Inspect outbound egress netflow to determine the external recipient and volume.",
                "Revoke active API tokens and sessions associated with the host."
            ])
        elif "indicator" in t_type or "malicious" in t_type:
            steps.extend([
                f"Add indicator ({entity or 'target'}) to organization-wide firewall and proxy deny-lists.",
                "Perform enterprise EDR sweep for any endpoint historical connections to this entity.",
                "Verify whether any payloads were downloaded or executed."
            ])
        else:
            steps.extend([
                "Review security event timeline and correlate with surrounding system activities.",
                "Verify authorization with the designated system owner or administrator.",
                "Maintain enhanced monitoring on the affected entities for the next 24 hours."
            ])

        return " | ".join(steps)

    def calculate_environment_security_score(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculates overall environment posture (0-100) and transparent sub-category risks.
        Higher score = better security health.
        """
        if not threats:
            return {
                "overall_score": 98.0,
                "health_grade": "A+",
                "breakdown": {
                    "authentication_risk": 5.0,
                    "network_risk": 5.0,
                    "indicator_risk": 0.0,
                    "behavioral_risk": 5.0,
                    "data_risk": 2.0
                }
            }

        # Calculate category penalties
        auth_risks = [t.get("risk_score", 0) for t in threats if any(k in t.get("threat_type", "").lower() for k in ["auth", "brute", "login"])]
        net_risks = [t.get("risk_score", 0) for t in threats if any(k in t.get("threat_type", "").lower() for k in ["port", "scan", "traffic", "recon"])]
        ind_risks = [t.get("risk_score", 0) for t in threats if any(k in t.get("threat_type", "").lower() for k in ["indicator", "malicious", "url", "domain"])]
        beh_risks = [t.get("anomaly_score", 0) for t in threats]
        data_risks = [t.get("risk_score", 0) for t in threats if any(k in t.get("threat_type", "").lower() for k in ["exfiltration", "data", "privilege"])]

        def avg_or_zero(vals):
            return sum(vals) / len(vals) if vals else 0.0

        auth_sub = min(100.0, avg_or_zero(auth_risks))
        net_sub = min(100.0, avg_or_zero(net_risks))
        ind_sub = min(100.0, avg_or_zero(ind_risks))
        beh_sub = min(100.0, avg_or_zero(beh_risks))
        data_sub = min(100.0, avg_or_zero(data_risks))

        # Weight categories
        weighted_risk = (
            auth_sub * 0.25 +
            net_sub * 0.25 +
            ind_sub * 0.20 +
            beh_sub * 0.15 +
            data_sub * 0.15
        )

        overall_score = max(10.0, round(100.0 - weighted_risk * 0.85, 1))

        if overall_score >= 90:
            grade = "A (Optimal)"
        elif overall_score >= 75:
            grade = "B (Good)"
        elif overall_score >= 60:
            grade = "C (Needs Attention)"
        elif overall_score >= 40:
            grade = "D (Elevated Risk)"
        else:
            grade = "F (Critical Vulnerability)"

        return {
            "overall_score": overall_score,
            "health_grade": grade,
            "breakdown": {
                "authentication_risk": round(auth_sub, 1),
                "network_risk": round(net_sub, 1),
                "indicator_risk": round(ind_sub, 1),
                "behavioral_risk": round(beh_sub, 1),
                "data_risk": round(data_sub, 1)
            }
        }
