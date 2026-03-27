# Author: Aayush — PDF Report Generator
"""
AEGIS Scanner — PDF Report Generator
Generates a professional PDF security assessment report from scan results.

Report sections:
1. Cover page with target URL, scan date, and overall risk level
2. Executive summary with severity breakdown
3. OWASP category summary
4. Detailed findings table (sorted by severity)
5. Remediation recommendations
6. Scan metadata (endpoints discovered, scan duration, model info)

Usage:
    from backend.utils.report_generator import ReportGenerator

    generator = ReportGenerator()
    pdf_path = generator.generate(scan_results)

Uses ReportLab for PDF creation.
"""

import os
import logging
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from backend.config import REPORT_OUTPUT_DIR

logger = logging.getLogger(__name__)

# Severity → colour mapping for the report
SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#CA8A04"),
    "Low": colors.HexColor("#2563EB"),
    "Info": colors.HexColor("#6B7280"),
}

RISK_LEVEL_COLORS = {
    "Safe": colors.HexColor("#16A34A"),
    "Low": colors.HexColor("#2563EB"),
    "Medium": colors.HexColor("#CA8A04"),
    "High": colors.HexColor("#EA580C"),
    "Critical": colors.HexColor("#DC2626"),
}


class ReportGenerator:
    """Generates a PDF security assessment report from scan results."""

    def __init__(self, output_dir=None):
        self.output_dir = output_dir or REPORT_OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Add custom paragraph styles for the report."""
        self.styles.add(ParagraphStyle(
            name="CoverTitle",
            parent=self.styles["Title"],
            fontSize=28,
            spaceAfter=10,
            textColor=colors.HexColor("#1E293B"),
            alignment=TA_CENTER,
        ))
        self.styles.add(ParagraphStyle(
            name="CoverSubtitle",
            parent=self.styles["Normal"],
            fontSize=14,
            textColor=colors.HexColor("#475569"),
            alignment=TA_CENTER,
            spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            name="SectionTitle",
            parent=self.styles["Heading1"],
            fontSize=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=20,
            spaceAfter=10,
        ))
        self.styles.add(ParagraphStyle(
            name="SubSection",
            parent=self.styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#334155"),
            spaceBefore=12,
            spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            name="FindingTitle",
            parent=self.styles["Normal"],
            fontSize=11,
            textColor=colors.HexColor("#1E293B"),
            fontName="Helvetica-Bold",
            spaceBefore=8,
            spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            name="BodyText2",
            parent=self.styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#475569"),
            spaceAfter=4,
            leading=13,
        ))
        self.styles.add(ParagraphStyle(
            name="SmallNote",
            parent=self.styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#94A3B8"),
            alignment=TA_CENTER,
        ))

    def generate(self, scan_results):
        """
        Generate a PDF report from scan results.

        Args:
            scan_results: dict with keys:
                target_url, scan_duration, risk_prediction,
                findings, recommendations, crawl_stats, model_info

        Returns:
            str — path to the generated PDF file
        """
        target_url = scan_results.get("target_url", "Unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        import re as _re
        safe_name = target_url.replace("://", "_").replace("/", "_")
        safe_name = _re.sub(r'[^a-zA-Z0-9_.\-]', '', safe_name).strip("_")
        filename = f"aegis_report_{safe_name}_{timestamp}.pdf"
        filepath = os.path.join(self.output_dir, filename)

        doc = SimpleDocTemplate(
            filepath,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        story = []

        # Build report sections
        story += self._build_cover_page(scan_results)
        story.append(PageBreak())
        story += self._build_executive_summary(scan_results)
        story += self._build_owasp_summary(scan_results)
        story += self._build_findings_table(scan_results)
        story.append(PageBreak())
        story += self._build_recommendations(scan_results)
        story += self._build_scan_metadata(scan_results)
        story += self._build_footer()

        doc.build(story)
        logger.info(f"PDF report generated: {filepath}")
        return filepath

    # ------------------------------------------------------------------
    # Section Builders
    # ------------------------------------------------------------------

    def _build_cover_page(self, results):
        """Build the cover / title page."""
        elements = []
        elements.append(Spacer(1, 60 * mm))

        elements.append(Paragraph("AEGIS SCANNER", self.styles["CoverTitle"]))
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph(
            "Web Application Security Assessment Report",
            self.styles["CoverSubtitle"],
        ))
        elements.append(Spacer(1, 15 * mm))

        # Target URL
        target = results.get("target_url", "N/A")
        elements.append(Paragraph(f"Target: {target}", self.styles["CoverSubtitle"]))

        # Date
        date_str = datetime.now().strftime("%d %B %Y, %H:%M")
        elements.append(Paragraph(f"Date: {date_str}", self.styles["CoverSubtitle"]))
        elements.append(Spacer(1, 10 * mm))

        # Risk level badge
        risk = results.get("risk_prediction", {})
        risk_level = risk.get("risk_level", "Unknown")
        confidence = risk.get("confidence", 0)

        risk_color = RISK_LEVEL_COLORS.get(risk_level, colors.gray)
        elements.append(Paragraph(
            f'Overall Risk Level: <font color="{risk_color.hexval()}">'
            f'<b>{risk_level.upper()}</b></font> '
            f'(confidence: {confidence:.0%})',
            self.styles["CoverSubtitle"],
        ))

        elements.append(Spacer(1, 30 * mm))
        elements.append(Paragraph(
            "Generated by AEGIS Scanner — NIT6150 Advanced Project, NMIT",
            self.styles["SmallNote"],
        ))

        return elements

    def _build_executive_summary(self, results):
        """Build the executive summary section."""
        elements = []
        elements.append(Paragraph("1. Executive Summary", self.styles["SectionTitle"]))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#E2E8F0"),
        ))

        risk = results.get("risk_prediction", {})
        risk_level = risk.get("risk_level", "Unknown")
        features = risk.get("features_summary", {})

        # Risk guidance
        recs = results.get("recommendations", {})
        guidance = recs.get("risk_guidance", {})
        summary_text = guidance.get("summary", "")
        action_text = guidance.get("action", "")
        priority_text = guidance.get("priority", "")

        elements.append(Paragraph(
            f"<b>Risk Level:</b> {risk_level} | "
            f"<b>Priority:</b> {priority_text}",
            self.styles["BodyText2"],
        ))
        elements.append(Paragraph(summary_text, self.styles["BodyText2"]))
        elements.append(Paragraph(
            f"<b>Recommended Action:</b> {action_text}",
            self.styles["BodyText2"],
        ))
        elements.append(Spacer(1, 5 * mm))

        # Severity breakdown table
        severity_data = features.get("findings_by_severity", {})
        if severity_data:
            elements.append(Paragraph(
                "Severity Breakdown", self.styles["SubSection"],
            ))

            table_data = [["Severity", "Count"]]
            for sev in ["Critical", "High", "Medium", "Low"]:
                count = severity_data.get(sev, 0)
                if count > 0:
                    table_data.append([sev, str(count)])

            if len(table_data) > 1:
                t = Table(table_data, colWidths=[80 * mm, 40 * mm])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]))
                elements.append(t)

        return elements

    def _build_owasp_summary(self, results):
        """Build the OWASP category summary section."""
        elements = []
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph(
            "2. OWASP Top 10 Coverage", self.styles["SectionTitle"],
        ))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#E2E8F0"),
        ))

        recs = results.get("recommendations", {})
        owasp_summary = recs.get("owasp_summary", {})

        if owasp_summary:
            table_data = [["OWASP Category", "Findings"]]
            for category, count in sorted(
                owasp_summary.items(), key=lambda x: x[1], reverse=True
            ):
                table_data.append([category, str(count)])

            t = Table(table_data, colWidths=[120 * mm, 30 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            elements.append(t)
        else:
            elements.append(Paragraph(
                "No OWASP-categorised findings.",
                self.styles["BodyText2"],
            ))

        return elements

    def _build_findings_table(self, results):
        """Build the detailed findings section."""
        elements = []
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph(
            "3. Detailed Findings", self.styles["SectionTitle"],
        ))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#E2E8F0"),
        ))

        findings = results.get("findings", [])

        if not findings:
            elements.append(Paragraph(
                "No vulnerabilities were discovered.",
                self.styles["BodyText2"],
            ))
            return elements

        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings_sorted = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "Info"), 5),
        )

        for i, finding in enumerate(findings_sorted, 1):
            sev = finding.get("severity", "Info")
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)

            elements.append(Paragraph(
                f'<font color="{sev_color.hexval()}">[{sev}]</font> '
                f'{finding.get("vuln_type", "Unknown")}',
                self.styles["FindingTitle"],
            ))

            details_text = (
                f'<b>Endpoint:</b> {finding.get("method", "GET")} '
                f'{finding.get("url", "N/A")}<br/>'
                f'<b>Parameter:</b> {finding.get("parameter", "N/A")}<br/>'
                f'<b>Confidence:</b> {finding.get("confidence", "N/A")}<br/>'
                f'<b>Evidence:</b> {_escape_xml(finding.get("evidence", "N/A"))}'
            )
            elements.append(Paragraph(details_text, self.styles["BodyText2"]))

            # Add a thin separator between findings
            if i < len(findings_sorted):
                elements.append(Spacer(1, 2 * mm))
                elements.append(HRFlowable(
                    width="100%", thickness=0.5,
                    color=colors.HexColor("#F1F5F9"),
                ))

        return elements

    def _build_recommendations(self, results):
        """Build the remediation recommendations section."""
        elements = []
        elements.append(Paragraph(
            "4. Remediation Recommendations", self.styles["SectionTitle"],
        ))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#E2E8F0"),
        ))

        recs = results.get("recommendations", {})
        rec_list = recs.get("recommendations", [])

        if not rec_list:
            elements.append(Paragraph(
                "No specific recommendations — application appears secure.",
                self.styles["BodyText2"],
            ))
            return elements

        for i, rec in enumerate(rec_list, 1):
            sev = rec.get("severity", "Info")
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)
            owasp_id = rec.get("owasp_id", "N/A")

            elements.append(Paragraph(
                f'<font color="{sev_color.hexval()}">[{sev}]</font> '
                f'{rec.get("finding_type", "Unknown")} '
                f'<font color="#94A3B8">({owasp_id})</font>',
                self.styles["FindingTitle"],
            ))

            # Description
            elements.append(Paragraph(
                _escape_xml(rec.get("description", "")),
                self.styles["BodyText2"],
            ))

            # Remediation steps
            steps = rec.get("remediation_steps", [])
            for j, step in enumerate(steps, 1):
                elements.append(Paragraph(
                    f"  {j}. {_escape_xml(step)}",
                    self.styles["BodyText2"],
                ))

            # References
            refs = rec.get("references", [])
            if refs:
                ref_text = " | ".join(
                    f'<link href="{ref}">{ref}</link>' for ref in refs
                )
                elements.append(Paragraph(
                    f'<font size="7" color="#94A3B8">Ref: {ref_text}</font>',
                    self.styles["BodyText2"],
                ))

            elements.append(Spacer(1, 3 * mm))

        return elements

    def _build_scan_metadata(self, results):
        """Build the scan metadata section."""
        elements = []
        elements.append(Spacer(1, 5 * mm))
        elements.append(Paragraph(
            "5. Scan Metadata", self.styles["SectionTitle"],
        ))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#E2E8F0"),
        ))

        crawl_stats = results.get("crawl_stats", {})
        model_info = results.get("model_info", {})
        duration = results.get("scan_duration", "N/A")

        meta_data = [
            ["Property", "Value"],
            ["Target URL", results.get("target_url", "N/A")],
            ["Scan Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan Duration", f"{duration}s" if isinstance(duration, (int, float)) else str(duration)],
            ["URLs Visited", str(crawl_stats.get("urls_visited", "N/A"))],
            ["Endpoints Discovered", str(crawl_stats.get("endpoints_discovered", "N/A"))],
            ["Forms Found", str(crawl_stats.get("forms_found", "N/A"))],
            ["Login Forms", str(crawl_stats.get("login_forms", "N/A"))],
            ["API Endpoints", str(crawl_stats.get("api_endpoints", "N/A"))],
            ["ML Model", model_info.get("model_type", "N/A")],
            ["Model Accuracy", str(model_info.get("training_accuracy", "N/A"))],
            ["Scanner Version", "AEGIS Scanner v1.0"],
        ]

        t = Table(meta_data, colWidths=[70 * mm, 80 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t)

        return elements

    def _build_footer(self):
        """Build the report footer."""
        elements = []
        elements.append(Spacer(1, 15 * mm))
        elements.append(HRFlowable(
            width="100%", thickness=1, color=colors.HexColor("#E2E8F0"),
        ))
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph(
            "This report was generated automatically by AEGIS Scanner, "
            "an AI-based web application vulnerability scanner developed "
            "as part of the NIT6150 Advanced Project at NMIT, Victoria University. "
            "Findings should be validated by a qualified security professional "
            "before taking action on production systems.",
            self.styles["SmallNote"],
        ))
        elements.append(Spacer(1, 3 * mm))
        elements.append(Paragraph(
            f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles["SmallNote"],
        ))

        return elements


# --------------------------------------------------------------------------
# Utility
# --------------------------------------------------------------------------
def _escape_xml(text):
    """Escape special XML characters for ReportLab Paragraph markup."""
    if not text:
        return ""
    text = str(text)
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    text = text.replace("'", "&apos;")
    return text