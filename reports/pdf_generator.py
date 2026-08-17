"""
VulnScan Lite - Professional PDF Security Report Generator

Generates executive security health assessment reports using ReportLab.
Uses in-memory stream buffer (io.BytesIO) and NumberedCanvas for dynamic two-pass page numbering.
"""

from datetime import datetime
import io
import re
from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and stamp total page count on running footers.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "VulnScan Lite — Web Security Health Report")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)

        footer_text = "Passive Analysis Only • Authorized Security Assessment"
        self.drawString(54, 32, footer_text)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()


def escape_xml(text: Any) -> str:
    """Escape XML special characters for safe ReportLab paragraph markup."""
    if text is None:
        return ""
    text_str = str(text)
    return (
        text_str.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def generate_pdf_report(scan_data: Dict[str, Any]) -> bytes:
    """
    Generate an in-memory PDF security report from a completed scan record.
    Returns bytes of the compiled PDF.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    # Styles Setup
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12,
    )

    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    subheading = ParagraphStyle(
        "SubHeading",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
    )

    meta_label = ParagraphStyle(
        "MetaLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#64748B"),
    )

    meta_val = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A"),
    )

    code_style = ParagraphStyle(
        "CodeBlock",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0F172A"),
    )

    disclaimer_style = ParagraphStyle(
        "DisclaimerText",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11.5,
        textColor=colors.HexColor("#92400E"),
    )

    story: List[Any] = []

    # 1. Document Title & Header
    target_url = scan_data.get("target_url") or "Unknown Target"
    scan_id = scan_data.get("id") or "N/A"
    score = scan_data.get("score")
    grade = scan_data.get("grade") or "N/A"
    completed_at = scan_data.get("completed_at") or scan_data.get("created_at") or ""
    date_str = ""
    if completed_at:
        try:
            dt = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            date_str = dt.strftime("%B %d, %Y at %H:%M UTC")
        except Exception:
            date_str = str(completed_at)

    story.append(Paragraph("VulnScan Lite", title_style))
    story.append(Paragraph("Web Security Configuration Assessment Report", subtitle_style))

    # Header Metadata Table
    header_meta_data = [
        [
            Paragraph("Target Domain:", meta_label),
            Paragraph(f"<b>{escape_xml(target_url)}</b>", meta_val),
            Paragraph("Assessment Date:", meta_label),
            Paragraph(escape_xml(date_str or "N/A"), meta_val),
        ],
        [
            Paragraph("Scan UUID:", meta_label),
            Paragraph(f"<font name='Courier'>{escape_xml(scan_id)}</font>", meta_val),
            Paragraph("Analyst / Author:", meta_label),
            Paragraph("Advaith K (B.Tech Cyber Security)", meta_val),
        ],
    ]
    t_header = Table(header_meta_data, colWidths=[85, 170, 95, 154])
    t_header.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(t_header)
    story.append(Spacer(1, 10))

    # 2. Mandatory Safety & Passive Assessment Notice
    disclaimer_box = [
        [
            Paragraph(
                "<b>Mandatory Authorization & Passive Inspection Notice:</b> Only scan websites you own or have explicit "
                "written permission to assess. This report reflects passive, non-intrusive reconnaissance (HTTP configuration, "
                "security headers, TLS parameters, and public CMS signatures). It contains zero active vulnerability exploitation, "
                "fuzzing, or crawling and does not replace a manual comprehensive penetration test.",
                disclaimer_style,
            )
        ]
    ]
    t_disc = Table(disclaimer_box, colWidths=[504])
    t_disc.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF3C7")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#F59E0B")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t_disc)
    story.append(Spacer(1, 12))

    # 3. Executive Summary & Scorecard
    story.append(Paragraph("1. Executive Summary & Security Posture", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))

    result_data = scan_data.get("result") or {}
    summary_data = result_data.get("summary") or {}
    findings: List[Dict[str, Any]] = result_data.get("findings") or []

    total_checks = summary_data.get("total") or summary_data.get("total_checks") or len(findings)
    passed_checks = summary_data.get("passed") or len([f for f in findings if f.get("status") == "PASS"])
    failed_checks = summary_data.get("failed") or len([f for f in findings if f.get("status") == "FAIL"])
    warning_checks = summary_data.get("warnings") or len([f for f in findings if f.get("status") == "WARNING"])

    grade_bg = colors.HexColor("#0F172A")
    if grade == "A":
        grade_bg = colors.HexColor("#059669")
    elif grade == "B":
        grade_bg = colors.HexColor("#0284C7")
    elif grade == "C":
        grade_bg = colors.HexColor("#D97706")
    elif grade == "D":
        grade_bg = colors.HexColor("#EA580C")
    elif grade == "F":
        grade_bg = colors.HexColor("#DC2626")

    score_card_data = [
        [
            Paragraph(
                f"<font size='22'><b>{score if score is not None else '--'}</b></font><font size='10' color='#64748B'> / 100</font><br/>"
                "<b>Security Health Score</b>",
                body_style,
            ),
            Paragraph(
                f"<font size='22' color='white'><b>{escape_xml(grade)}</b></font><br/>"
                "<font color='white'><b>Rating Grade</b></font>",
                ParagraphStyle("GradeStyle", parent=body_style, alignment=1, textColor=colors.white),
            ),
            Paragraph(
                f"<b>Total Evaluated Checks:</b> {total_checks}<br/>"
                f"<font color='#059669'><b>Passed Checks:</b> {passed_checks}</font><br/>"
                f"<font color='#DC2626'><b>Failed / Missing:</b> {failed_checks}</font><br/>"
                f"<font color='#D97706'><b>Warnings:</b> {warning_checks}</font>",
                body_style,
            ),
        ]
    ]

    t_score = Table(score_card_data, colWidths=[160, 110, 234])
    t_score.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#F8FAFC")),
                ("BACKGROUND", (1, 0), (1, 0), grade_bg),
                ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(t_score)
    story.append(Spacer(1, 12))

    # 4. Technical Configuration Diagnostics
    story.append(Paragraph("2. Technical Infrastructure Diagnostics", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))

    http_info = result_data.get("http") or {}
    tls_info = result_data.get("tls") or {}
    cms_info = result_data.get("cms") or {}

    diag_data = [
        [
            Paragraph("<b>Component</b>", meta_label),
            Paragraph("<b>Inspection Summary & Telemetry</b>", meta_label),
            Paragraph("<b>Outcome</b>", meta_label),
        ],
        [
            Paragraph("HTTP / HTTPS", body_style),
            Paragraph(
                f"Status: <b>{http_info.get('status_code', 'N/A')}</b> • Latency: <b>{http_info.get('response_time', 'N/A')}s</b> • Content: {escape_xml(http_info.get('content_type', 'N/A'))}",
                body_style,
            ),
            Paragraph("OK" if http_info.get("success") else "FAIL", body_style),
        ],
        [
            Paragraph("TLS / SSL", body_style),
            Paragraph(
                f"Protocol: <b>{escape_xml(tls_info.get('connection', {}).get('tls_version') or 'N/A')}</b> • Cipher: {escape_xml(tls_info.get('connection', {}).get('cipher_suite') or 'N/A')}",
                body_style,
            ),
            Paragraph(escape_xml(tls_info.get("status", "N/A")), body_style),
        ],
        [
            Paragraph("CMS Detection", body_style),
            Paragraph(
                f"Platform: <b>{escape_xml(cms_info.get('cms') or 'None detected')}</b> • Confidence: {escape_xml(cms_info.get('confidence') or 'N/A')}",
                body_style,
            ),
            Paragraph("Identified" if cms_info.get("detected") else "N/A", body_style),
        ],
    ]

    t_diag = Table(diag_data, colWidths=[95, 340, 69])
    t_diag.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t_diag)
    story.append(Spacer(1, 14))

    # 5. Security Findings Breakdown
    story.append(Paragraph("3. Detailed Security Checks & Findings", section_heading))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))

    if findings:
        findings_table_data = [
            [
                Paragraph("<b>Check Name</b>", meta_label),
                Paragraph("<b>Category</b>", meta_label),
                Paragraph("<b>Status</b>", meta_label),
                Paragraph("<b>Severity</b>", meta_label),
                Paragraph("<b>Impact</b>", meta_label),
            ]
        ]

        for f in findings:
            status_color = "#059669" if f.get("status") == "PASS" else ("#DC2626" if f.get("status") == "FAIL" else "#D97706")
            pts = f.get("points", 0)
            pts_str = f"{pts} pts" if pts < 0 else "--"

            cat_raw = f.get("category", "")
            cat_name = {
                "security_headers": "Headers",
                "tls": "TLS/SSL",
                "network": "HTTP",
                "cms": "CMS",
            }.get(cat_raw, cat_raw)

            findings_table_data.append([
                Paragraph(f"<b>{escape_xml(f.get('name', 'Unknown'))}</b><br/><font color='#64748B' size='7.5'>{escape_xml(f.get('details', ''))}</font>", body_style),
                Paragraph(escape_xml(cat_name), body_style),
                Paragraph(f"<font color='{status_color}'><b>{escape_xml(f.get('status', ''))}</b></font>", body_style),
                Paragraph(escape_xml(f.get("severity", "INFO")), body_style),
                Paragraph(pts_str, body_style),
            ])

        t_findings = Table(findings_table_data, colWidths=[210, 75, 75, 75, 69])
        t_findings.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(t_findings)
    else:
        story.append(Paragraph("All evaluated security checks passed.", body_style))

    story.append(Spacer(1, 14))

    # 6. Actionable Remediation Guidance
    failed_remediations = [f for f in findings if f.get("status") in ("FAIL", "WARNING") and f.get("remediation")]

    if failed_remediations:
        story.append(KeepTogether([
            Paragraph("4. Hardening & Remediation Guidance", section_heading),
            HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8),
        ]))

        for item in failed_remediations:
            rem = item.get("remediation") or {}
            rem_title = rem.get("title") or item.get("name")
            why = rem.get("why_it_matters", "")
            recommendation = rem.get("recommendation", "")
            configs: Dict[str, str] = rem.get("configuration_examples") or {}

            rem_elements: List[Any] = [
                Paragraph(f"• <b>{escape_xml(rem_title)}</b> ({escape_xml(item.get('name'))})", subheading),
            ]

            if why:
                rem_elements.append(
                    Paragraph(f"<b>Technical Rationale & Risk:</b> {escape_xml(why)}", body_style)
                )
            if recommendation:
                rem_elements.append(
                    Paragraph(f"<b>Recommendation:</b> {escape_xml(recommendation)}", body_style)
                )

            # Configuration Snippets Table
            if configs:
                for server, code in configs.items():
                    code_clean = escape_xml(code).replace("\n", "<br/>&nbsp;&nbsp;")
                    snippet_data = [
                        [Paragraph(f"<b>{escape_xml(server)} Configuration Reference:</b>", meta_label)],
                        [Paragraph(code_clean, code_style)],
                    ]
                    t_snip = Table(snippet_data, colWidths=[494])
                    t_snip.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
                                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
                                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                                ("TOPPADDING", (0, 0), (-1, -1), 3),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                            ]
                        )
                    )
                    rem_elements.append(Spacer(1, 3))
                    rem_elements.append(t_snip)

            rem_elements.append(Spacer(1, 8))
            story.append(KeepTogether(rem_elements))

    # Build the document into bytes
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()
