"""
Professional PDF Security Report Generator
Generates executive-level cybersecurity reports using ReportLab.
"""

import os
from datetime import datetime
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from backend.app.config import settings


def generate_security_pdf_report(
    report_title: str,
    output_filename: str,
    total_events: int,
    threats: List[Dict[str, Any]],
    security_score: float,
    generated_by: str = "SOC Analyst"
) -> str:
    """
    Creates an executive cybersecurity analysis PDF report and returns the absolute file path.
    """
    file_path = os.path.join(settings.REPORTS_DIR, output_filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=14
    )

    heading2_style = ParagraphStyle(
        'ReportH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=14,
        spaceAfter=8
    )

    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#334155'),
        leading=13
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        textColor=colors.white
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("CYBER THREAT DETECTOR", title_style))
    story.append(Paragraph("AI-Powered Threat Detection & Security Intelligence Platform — Executive Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#0284c7'), spaceAfter=14))

    # 2. Metadata Information Block
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    crit_count = sum(1 for t in threats if str(t.get('severity', '')).upper() == 'CRITICAL')
    high_count = sum(1 for t in threats if str(t.get('severity', '')).upper() == 'HIGH')
    med_count = sum(1 for t in threats if str(t.get('severity', '')).upper() == 'MEDIUM')
    low_count = sum(1 for t in threats if str(t.get('severity', '')).upper() == 'LOW')

    meta_data = [
        [
            Paragraph(f"<b>Generated:</b> {now_str}", body_style),
            Paragraph(f"<b>Analyst:</b> {generated_by}", body_style)
        ],
        [
            Paragraph(f"<b>Total Events Evaluated:</b> {total_events}", body_style),
            Paragraph(f"<b>Security Health Score:</b> {security_score:.1f}/100", body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[260, 260])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 3. Executive Metrics Table
    story.append(Paragraph("1. Executive Summary & Threat Breakdown", heading2_style))
    exec_summary_text = (
        f"Defensive security inspection evaluated a total of {total_events} security records across the target environment. "
        f"A total of {len(threats)} potential threats were identified by the hybrid detection engine, including "
        f"{crit_count} Critical, {high_count} High, {med_count} Medium, and {low_count} Low severity alerts. "
        f"The composite Security Health Score is established at {security_score:.1f}/100."
    )
    story.append(Paragraph(exec_summary_text, body_style))
    story.append(Spacer(1, 10))

    metrics_data = [
        [
            Paragraph("Metric", table_header_style),
            Paragraph("Value", table_header_style),
            Paragraph("Risk Implication", table_header_style)
        ],
        [
            Paragraph("Critical Threats", body_style),
            Paragraph(str(crit_count), body_style),
            Paragraph("Immediate containment and host isolation required", body_style)
        ],
        [
            Paragraph("High Threats", body_style),
            Paragraph(str(high_count), body_style),
            Paragraph("Prioritized investigation within standard SOC SLA", body_style)
        ],
        [
            Paragraph("Medium Threats", body_style),
            Paragraph(str(med_count), body_style),
            Paragraph("Suspicious activity, monitor source IP / account", body_style)
        ],
        [
            Paragraph("Low / Informational", body_style),
            Paragraph(str(low_count), body_style),
            Paragraph("Low risk anomalies, baseline tracking", body_style)
        ]
    ]

    metrics_table = Table(metrics_data, colWidths=[130, 80, 310])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 14))

    # 4. Top Detected Threats Table
    story.append(Paragraph("2. Prioritized Threat Findings", heading2_style))

    threat_rows = [
        [
            Paragraph("ID", table_header_style),
            Paragraph("Type", table_header_style),
            Paragraph("Severity", table_header_style),
            Paragraph("Score", table_header_style),
            Paragraph("Source / Entity", table_header_style),
            Paragraph("Detection Rationale", table_header_style)
        ]
    ]

    # Show top 10 threats in report table
    for idx, t in enumerate(threats[:12], 1):
        sev = str(t.get('severity', 'LOW')).upper()
        sev_color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else ("#f59e0b" if sev == "MEDIUM" else "#10b981"))
        
        entity = t.get('source_ip') or t.get('username') or t.get('domain') or "N/A"
        expl = t.get('explanation') or "Flagged by detection engine"
        if len(expl) > 75:
            expl = expl[:72] + "..."

        threat_rows.append([
            Paragraph(str(t.get('id', idx)), body_style),
            Paragraph(str(t.get('threat_type', 'Unknown')), body_style),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", body_style),
            Paragraph(f"{float(t.get('risk_score', 0)):.1f}", body_style),
            Paragraph(str(entity), body_style),
            Paragraph(expl, body_style)
        ])

    if len(threat_rows) == 1:
        threat_rows.append([
            Paragraph("N/A", body_style),
            Paragraph("No active threats detected", body_style),
            Paragraph("CLEAR", body_style),
            Paragraph("0.0", body_style),
            Paragraph("All entities normal", body_style),
            Paragraph("Baseline security conditions satisfied.", body_style)
        ])

    threats_table = Table(threat_rows, colWidths=[30, 95, 60, 45, 90, 200])
    threats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
    ]))
    story.append(threats_table)
    story.append(Spacer(1, 14))

    # 5. Defensive Recommendations
    story.append(Paragraph("3. Recommended Defensive Remediations", heading2_style))
    recs = [
        "1. <b>Network Perimeter:</b> Block confirmed malicious source IPs on external firewalls and edge ingress routers.",
        "2. <b>Identity & Access Management:</b> Enforce Multi-Factor Authentication (MFA) and mandate credential resets for accounts subject to brute-force or credential stuffing patterns.",
        "3. <b>DNS & Endpoint Security:</b> Blacklist suspicious DGA domains on local DNS resolvers and trigger automated EDR scans on affected internal endpoints.",
        "4. <b>Traffic Monitoring:</b> Isolate hosts exhibiting high outbound data transfer or uncommon destination port connections (e.g. ports 4444, 1337, 8888).",
        "5. <b>Threat Intel Ingestion:</b> Subscribe internal SIEM/SOC platforms to updated Threat Intelligence feeds for real-time proactive indicator blocking."
    ]
    for r in recs:
        story.append(Paragraph(r, body_style))
        story.append(Spacer(1, 4))

    # 6. Disclaimer
    story.append(Spacer(1, 10))
    disclaimer_text = (
        "<i>Disclaimer: This document is generated by the Cyber Threat Detector defensive monitoring platform for authorized security evaluation. "
        "All detection scores, indicators, and anomaly rankings are defensive analytical assessments. Never execute unauthorized actions or offensive testing.</i>"
    )
    story.append(Paragraph(disclaimer_text, body_style))

    doc.build(story)
    return file_path
