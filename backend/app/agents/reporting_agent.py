import io
from datetime import datetime, timezone
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

from app.models.project import Project
from app.models.finding import Finding
from app.models.scan import ScanJob


class ReportingAgent:
    """
    Agent 12 — Reporting and Compliance Agent
    Produces evidence-backed summaries, maps findings to CWE/OWASP controls,
    and generates downloadable JSON and PDF reports.
    """

    @classmethod
    def generate_json_report(cls, db: Session, project_id: str) -> Dict[str, Any]:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError("Project not found")

        findings: List[Finding] = db.query(Finding).filter(Finding.project_id == project_id).all()
        scans: List[ScanJob] = db.query(ScanJob).filter(ScanJob.project_id == project_id).all()

        findings_data = []
        for f in findings:
            evidence_list = [
                {
                    "type": ev.evidence_type,
                    "file": ev.file_path,
                    "lines": f"{ev.start_line}-{ev.end_line}",
                    "snippet": ev.sanitized_snippet
                }
                for ev in f.evidence
            ]
            findings_data.append({
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "category": f.category.value,
                "scanner_name": f.scanner_name,
                "scanner_rule_id": f.scanner_rule_id,
                "cwe_id": f.cwe_id,
                "original_severity": f.original_severity.value,
                "cvss_score": f.cvss_score,
                "internal_risk_level": f.internal_risk_level.value,
                "internal_risk_score": f.internal_risk_score,
                "risk_rationale": f.risk_rationale,
                "status": f.status.value,
                "first_seen_at": f.first_seen_at.isoformat(),
                "last_seen_at": f.last_seen_at.isoformat(),
                "evidence": evidence_list
            })

        return {
            "platform": "SentinelAI Security Intelligence Platform",
            "report_version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "project": {
                "id": project.id,
                "name": project.name,
                "tenant_id": project.tenant_id
            },
            "summary_metrics": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.internal_risk_level.value == "CRITICAL"),
                "high": sum(1 for f in findings if f.internal_risk_level.value == "HIGH"),
                "medium": sum(1 for f in findings if f.internal_risk_level.value == "MEDIUM"),
                "low": sum(1 for f in findings if f.internal_risk_level.value == "LOW"),
                "info": sum(1 for f in findings if f.internal_risk_level.value == "INFO"),
                "total_scans": len(scans)
            },
            "findings": findings_data,
            "methodology_and_limitations": (
                "Assessments are conducted using bounded static, dependency, secret, and dynamic security analyzers. "
                "AI may interpret evidence, but deterministic scanners are authoritative. "
                "A clean assessment indicates no findings from executed rules; untested components are not certified secure."
            )
        }

    @classmethod
    def generate_pdf_report(cls, db: Session, project_id: str) -> bytes:
        data = cls.generate_json_report(db, project_id)
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, leading=24, textColor=colors.HexColor('#0F172A'))
        h2_style = ParagraphStyle('H2Style', parent=styles['Heading2'], fontSize=14, leading=18, textColor=colors.HexColor('#1E293B'))
        body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor('#334155'))
        code_style = ParagraphStyle('CodeStyle', parent=styles['Normal'], fontSize=8, leading=10, textColor=colors.HexColor('#0F172A'), fontName="Courier")

        elements = []

        # Title & Meta
        elements.append(Paragraph("SentinelAI Security Assessment Report", title_style))
        elements.append(Paragraph(f"Project: <b>{data['project']['name']}</b> | Generated: {data['generated_at'][:19]} UTC", body_style))
        elements.append(Spacer(1, 14))

        # Executive Summary Table
        metrics = data["summary_metrics"]
        summary_table_data = [
            ["Total Findings", "Critical", "High", "Medium", "Low", "Scans Completed"],
            [
                str(metrics["total_findings"]),
                str(metrics["critical"]),
                str(metrics["high"]),
                str(metrics["medium"]),
                str(metrics["low"]),
                str(metrics["total_scans"])
            ]
        ]
        t = Table(summary_table_data, colWidths=[90, 80, 80, 80, 80, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 18))

        # Findings Detail
        elements.append(Paragraph("Detailed Security Findings", h2_style))
        elements.append(Spacer(1, 8))

        for f in data["findings"]:
            elements.append(Paragraph(f"<b>[{f['internal_risk_level']}] {f['title']}</b>", h2_style))
            meta_line = f"Category: {f['category']} | Scanner: {f['scanner_name']} ({f['scanner_rule_id']}) | CWE: {f['cwe_id'] or 'N/A'} | Status: {f['status']}"
            elements.append(Paragraph(meta_line, body_style))
            elements.append(Paragraph(f"<b>Description:</b> {f['description']}", body_style))
            elements.append(Paragraph(f"<b>Internal Risk Rationale:</b> {f['risk_rationale']}", body_style))
            
            if f.get("evidence"):
                ev = f["evidence"][0]
                elements.append(Paragraph(f"<b>Evidence ({ev['type']}):</b> {ev['file'] or 'N/A'}", body_style))
                clean_snippet = ev["snippet"][:300].replace("<", "&lt;").replace(">", "&gt;")
                elements.append(Paragraph(f"<pre>{clean_snippet}</pre>", code_style))

            elements.append(Spacer(1, 10))

        # Methodology & Limitations Disclaimer
        elements.append(Spacer(1, 14))
        elements.append(Paragraph("<b>Methodology & Limitations:</b>", body_style))
        elements.append(Paragraph(data["methodology_and_limitations"], body_style))

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()


reporting_agent = ReportingAgent()
