from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

PAGE_WIDTH, PAGE_HEIGHT = A4
PRIMARY_COLOR = colors.HexColor("#143C6B")
SECONDARY_BG = colors.HexColor("#F3F5F7")
DARK_TEXT = colors.HexColor("#1F2937")
ACCENT_GRAY = colors.HexColor("#64748B")
BORDER = colors.HexColor("#D1D5DB")

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#7F1D1D"),
    "High": colors.HexColor("#B91C1C"),
    "Medium": colors.HexColor("#c2410c"),
    "Low": colors.HexColor("#b45309"),
    "Information": colors.HexColor("#2563EB"),
    "Unknown": colors.HexColor("#6B7280"),
}


def get_styles():
    base = getSampleStyleSheet()
    base.add(
        ParagraphStyle(
            name="SC_Title",
            fontName="Helvetica-Bold",
            fontSize=30,
            leading=34,
            textColor=PRIMARY_COLOR,
            alignment=TA_LEFT,
            spaceAfter=10,
        )
    )
    base.add(
        ParagraphStyle(
            name="SC_Subtitle",
            fontName="Helvetica",
            fontSize=13,
            leading=17,
            textColor=ACCENT_GRAY,
            alignment=TA_LEFT,
            spaceAfter=8,
        )
    )
    base.add(
        ParagraphStyle(
            name="SC_H1",
            fontName="Helvetica-Bold",
            fontSize=17,
            leading=22,
            textColor=PRIMARY_COLOR,
            spaceAfter=8,
            spaceBefore=8,
        )
    )
    base.add(
        ParagraphStyle(
            name="SC_H2",
            fontName="Helvetica-Bold",
            fontSize=12.5,
            leading=16,
            textColor=PRIMARY_COLOR,
            spaceAfter=6,
            spaceBefore=6,
        )
    )
    base.add(
        ParagraphStyle(
            name="SC_Body",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=DARK_TEXT,
            spaceAfter=4,
        )
    )
    base.add(
        ParagraphStyle(
            name="SC_Small",
            fontName="Helvetica",
            fontSize=8.5,
            leading=11,
            textColor=ACCENT_GRAY,
            spaceAfter=2,
        )
    )
    base.add(
        ParagraphStyle(
            name="SC_Label",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=DARK_TEXT,
        )
    )
    return base


def safe_text(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, bool):
        return str(value)
    text = str(value).strip()
    return text if text else "N/A"


def normalize_results(raw: dict[str, Any]) -> dict[str, Any]:
    findings = raw.get("findings") or []
    evidence = []
    for key in ("detection_evidence", "algorithm_evidence", "implementation_evidence"):
        for item in raw.get(key, []) or []:
            s = safe_text(item)
            if s != "N/A" and s not in evidence:
                evidence.append(s)

    if not evidence:
        ev = raw.get("evidence", {}) or {}
        for m in ev.get("matched_identifiers", []) or []:
            evidence.append(safe_text(m))
        for k, v in (ev.get("matched_parameters", {}) or {}).items():
            evidence.append(f"{k} = {safe_text(v)}")

    return {
        "project_name": raw.get("project_name") or raw.get("folder_name") or "Unknown Project",
        "analysis_date": raw.get("analysis_date") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "client_name": raw.get("client_name") or "Client X",
        "logo_path": raw.get("logo_path"),
        "tool_version": raw.get("tool_version") or raw.get("scancrypt_version") or "1.0",
        "algorithm": raw.get("algorithm") or raw.get("overall_algorithm") or "Unknown",
        "security_level": raw.get("security_level") or raw.get("overall_security_level") or "Unknown",
        "implementation_type": raw.get("implementation_type") or raw.get("overall_implementation_type") or "Unknown",
        "overall_risk": raw.get("overall_risk") or raw.get("risk") or "Unknown",
        "language": raw.get("language") or raw.get("programming_language") or "C/C++",
        "build_system": raw.get("build_system") or "Not detected",
        "files": int(raw.get("files") or raw.get("total_files") or 0),
        "source_files": int(raw.get("source_files") or raw.get("c_source_files") or raw.get("c_files") or 0),
        "header_files": int(raw.get("header_files") or raw.get("h_files") or 0),
        "lines_of_code": int(raw.get("lines_of_code") or raw.get("total_loc") or 0),
        "analysis_confidence": safe_text(raw.get("analysis_confidence") or raw.get("confidence") or "N/A"),
        "detection_confidence": safe_text(raw.get("detection_confidence") or raw.get("analysis_confidence") or raw.get("confidence") or "N/A"),
        "rules_executed": int(raw.get("rules_executed") or len(findings)),
        "rules_passed": int(raw.get("rules_passed") or sum(1 for x in findings if safe_text(x.get("status")).lower() == "passed")),
        "rules_failed": int(raw.get("rules_failed") or sum(1 for x in findings if safe_text(x.get("status")).lower() == "failed")),
        "analysis_duration": safe_text(raw.get("analysis_duration") or "N/A"),
        "detection_evidence": evidence,
        "findings": findings,
        "analysed_files": raw.get("analysed_files") or raw.get("files_list") or [],
        "scan_configuration": safe_text(raw.get("scan_configuration") or "Not available"),
        "supported_algorithms": raw.get("supported_algorithms") or ["ML-DSA (Dilithium)", "ML-KEM (Kyber)"],
        "supported_implementation_types": raw.get("supported_implementation_types") or [
            "Portable C / Reference",
            "AVX2 Optimized",
            "ARM Cortex-M / Embedded",
            "Masked Implementation",
            "Hardware / FPGA",
        ],
    }


def _resolve_logo_path(possible_logo_path: str | None) -> str | None:
    if possible_logo_path:
        p = Path(possible_logo_path)
        if p.exists() and p.is_file():
            return str(p)

    uploads_dir = Path(__file__).resolve().parent / "static" / "uploads"
    if not uploads_dir.exists():
        return None
    for logo in uploads_dir.glob("company_logo.*"):
        if logo.is_file():
            return str(logo)
    return None


def badge(text: str, severity: str | None = None) -> Table:
    color = SEVERITY_COLORS.get(severity or text, colors.HexColor("#475569"))
    table = Table(
        [[Paragraph(f"<font color='white'><b>{text}</b></font>", get_styles()["SC_Label"])]],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ],
    )
    return table


def header_table(key: str, value: str) -> Table:
    styles = get_styles()
    return Table(
        [[Paragraph(f"<b>{key}</b>", styles["SC_Label"]), Paragraph(safe_text(value), styles["SC_Body"])]],
        colWidths=[50 * mm, 115 * mm],
        style=[
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ],
    )


def summary_card(key: str, value: str) -> Table:
    styles = get_styles()
    return Table(
        [[Paragraph(f"<b>{key}</b>", styles["SC_Label"]), Paragraph(safe_text(value), styles["SC_Body"])]],
        style=[
            ("BACKGROUND", (0, 0), (-1, -1), SECONDARY_BG),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ],
    )


def get_footer(canvas, doc):
    canvas.saveState()
    footer_text = f"ScanCrypt · Generated {datetime.now():%Y-%m-%d %H:%M:%S}"
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(ACCENT_GRAY)
    canvas.drawString(20 * mm, 15 * mm, footer_text)
    page_text = f"Page {doc.page}"
    canvas.drawRightString(PAGE_WIDTH - 20 * mm, 15 * mm, page_text)
    canvas.restoreState()


def _draw_page_branding(canvas, doc, normalized_results: dict[str, Any]):
    page_w, page_h = A4
    logo_path = _resolve_logo_path(normalized_results.get("logo_path"))

    # Subtle background logo on each page
    if logo_path:
        try:
            canvas.saveState()
            if hasattr(canvas, "setFillAlpha"):
                canvas.setFillAlpha(0.08)
            logo_w = 110 * mm
            logo_h = 110 * mm
            x = (page_w - logo_w) / 2
            y = (page_h - logo_h) / 2
            canvas.drawImage(
                ImageReader(logo_path),
                x,
                y,
                width=logo_w,
                height=logo_h,
                preserveAspectRatio=True,
                mask="auto",
            )
            canvas.restoreState()
        except Exception:
            # Fallback to subtle text mark
            canvas.saveState()
            if hasattr(canvas, "setFillAlpha"):
                canvas.setFillAlpha(0.05)
            canvas.setFillColor(colors.HexColor("#94A3B8"))
            canvas.setFont("Helvetica-Bold", 46)
            canvas.drawCentredString(page_w / 2, page_h / 2, "ScanCrypt")
            canvas.restoreState()
    else:
        canvas.saveState()
        if hasattr(canvas, "setFillAlpha"):
            canvas.setFillAlpha(0.05)
        canvas.setFillColor(colors.HexColor("#94A3B8"))
        canvas.setFont("Helvetica-Bold", 46)
        canvas.drawCentredString(page_w / 2, page_h / 2, "ScanCrypt")
        canvas.restoreState()

    # Diagonal watermark with date/time + client
    watermark_date = safe_text(normalized_results.get("analysis_date") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    watermark_client = safe_text(normalized_results.get("client_name") or "Client X")
    watermark_text = f"{watermark_client} | {watermark_date}"

    canvas.saveState()
    if hasattr(canvas, "setFillAlpha"):
        canvas.setFillAlpha(0.13)
    canvas.setFillColor(colors.HexColor("#CBD5E1"))
    canvas.setFont("Helvetica-Bold", 24)
    canvas.translate(page_w / 2, page_h / 2)
    canvas.rotate(35)
    canvas.drawCentredString(0, 0, watermark_text)
    canvas.restoreState()


def _on_page(canvas, doc, normalized_results: dict[str, Any]):
    _draw_page_branding(canvas, doc, normalized_results)
    get_footer(canvas, doc)


def create_cover_page(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    project_name = safe_text(results.get("project_name"))
    analysis_timestamp = safe_text(results.get("analysis_date"))
    version = safe_text(results.get("tool_version"))
    algorithm = safe_text(results.get("algorithm"))
    security_level = safe_text(results.get("security_level"))
    implementation_type = safe_text(results.get("implementation_type"))
    overall_risk = safe_text(results.get("overall_risk"))

    story: list[Any] = []
    story.append(Spacer(1, 28 * mm))
    story.append(Paragraph("ScanCrypt", styles["SC_Title"]))
    story.append(Paragraph("Post-Quantum Cryptographic Security Assessment", styles["SC_Subtitle"]))
    story.append(Spacer(1, 8 * mm))

    key_values = [
        [Paragraph("<b>Project Name</b>", styles["SC_Label"]), Paragraph(project_name, styles["SC_Body"])],
        [Paragraph("<b>Analysis Date</b>", styles["SC_Label"]), Paragraph(analysis_timestamp, styles["SC_Body"])],
        [Paragraph("<b>ScanCrypt Version</b>", styles["SC_Label"]), Paragraph(version, styles["SC_Body"])],
        [Paragraph("<b>Algorithm</b>", styles["SC_Label"]), Paragraph(algorithm, styles["SC_Body"])],
        [Paragraph("<b>Security Level</b>", styles["SC_Label"]), Paragraph(security_level, styles["SC_Body"])],
        [Paragraph("<b>Implementation Type</b>", styles["SC_Label"]), Paragraph(implementation_type, styles["SC_Body"])],
    ]
    details_table = Table(key_values, colWidths=[50 * mm, 115 * mm], hAlign="LEFT")
    details_table.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(details_table)
    story.append(Spacer(1, 6 * mm))
    story.append(badge(overall_risk, overall_risk if overall_risk in SEVERITY_COLORS else None))
    story.append(Spacer(1, 8 * mm))
    story.append(
        Paragraph(
            "<b>Confidentiality Notice</b>", styles["SC_H2"]
        )
    )
    story.append(
        Paragraph(
            "This document contains confidential assessment details based on ScanCrypt analysis. Unauthorized disclosure is prohibited.",
            styles["SC_Body"],
        )
    )
    story.append(Paragraph("Report generated automatically by ScanCrypt.", styles["SC_Small"]))
    story.append(PageBreak())
    return story


def create_executive_summary(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    findings = results.get("findings", []) or []
    severity_counts = get_severity_counts(findings)
    rules_executed = results.get("rules_executed", len(findings))
    rules_passed = results.get("rules_passed", sum(1 for item in findings if item.get("status", "Passed").lower() == "passed"))
    rules_failed = results.get("rules_failed", sum(1 for item in findings if item.get("status", "Failed").lower() == "failed"))
    confidence = safe_text(results.get("analysis_confidence", "N/A"))
    detection_confidence = safe_text(results.get("detection_confidence", confidence))

    story: list[Any] = []
    story.append(Paragraph("Executive Summary", styles["SC_H1"]))

    summary_data = [
        [summary_card("Overall Risk", safe_text(results.get("overall_risk", "Unknown"))), summary_card("Algorithm", safe_text(results.get("algorithm", "Unknown")))],
        [summary_card("Security Level", safe_text(results.get("security_level", "Unknown"))), summary_card("Implementation Type", safe_text(results.get("implementation_type", "Unknown")))],
        [summary_card("Programming Language", safe_text(results.get("language", "C/C++"))), summary_card("Build System", safe_text(results.get("build_system", "Unknown")))],
        [summary_card("Files", safe_text(results.get("files", 0))), summary_card("Source Files", safe_text(results.get("source_files", 0)))],
        [summary_card("Header Files", safe_text(results.get("header_files", 0))), summary_card("Lines of Code", safe_text(results.get("lines_of_code", 0)))],
        [summary_card("Rules Executed", safe_text(rules_executed)), summary_card("Rules Passed", safe_text(rules_passed))],
        [summary_card("Rules Failed", safe_text(rules_failed)), summary_card("Analysis Confidence", confidence)],
        [summary_card("Detection Confidence", detection_confidence), summary_card("Analysis Duration", safe_text(results.get("analysis_duration", "N/A")))],
    ]
    for row in summary_data:
        row_table = Table([row], colWidths=[82 * mm, 82 * mm])
        row_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]))
        story.append(row_table)
        story.append(Spacer(1, 2 * mm))

    badge_items = []
    for label in ["Critical", "High", "Medium", "Low", "Information"]:
        badge_items.append(badge(f"{label}: {severity_counts.get(label, 0)}", label))
        badge_items.append(Spacer(1, 2 * mm))
    story.extend(badge_items)
    story.append(PageBreak())
    return story


def create_project_inspection(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    story: list[Any] = []
    story.append(Paragraph("Project Inspection", styles["SC_H1"]))

    table_content = [
        [Paragraph("<b>Algorithm</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("algorithm", "Unknown")), styles["SC_Body"])],
        [Paragraph("<b>Security Level</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("security_level", "Unknown")), styles["SC_Body"])],
        [Paragraph("<b>Implementation Type</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("implementation_type", "Unknown")), styles["SC_Body"])],
        [Paragraph("<b>Programming Language</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("language", "C/C++")), styles["SC_Body"])],
        [Paragraph("<b>Build System</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("build_system", "Unknown")), styles["SC_Body"])],
        [Paragraph("<b>Files</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("files", 0)), styles["SC_Body"])],
        [Paragraph("<b>Source Files</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("source_files", 0)), styles["SC_Body"])],
        [Paragraph("<b>Header Files</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("header_files", 0)), styles["SC_Body"])],
        [Paragraph("<b>Lines of Code</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("lines_of_code", 0)), styles["SC_Body"])],
        [Paragraph("<b>Detection Confidence</b>", styles["SC_Label"]), Paragraph(safe_text(results.get("detection_confidence", "N/A")), styles["SC_Body"])],
    ]

    table = Table(table_content, colWidths=[50 * mm, 115 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), SECONDARY_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#E2E8F0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Detection Evidence", styles["SC_H2"]))

    evidence_items = results.get("detection_evidence", []) or []
    if evidence_items:
        for item in evidence_items:
            story.append(Paragraph(f"• {safe_text(item)}", styles["SC_Body"]))
    else:
        story.append(Paragraph("No detection evidence was reported.", styles["SC_Body"]))
    story.append(PageBreak())
    return story


def create_findings_summary(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    story: list[Any] = []
    story.append(Paragraph("Findings Summary", styles["SC_H1"]))
    findings = results.get("findings", []) or []
    table_data = [[
        Paragraph("<b>Rule ID</b>", styles["SC_Label"]),
        Paragraph("<b>Severity</b>", styles["SC_Label"]),
        Paragraph("<b>Category</b>", styles["SC_Label"]),
        Paragraph("<b>Status</b>", styles["SC_Label"]),
        Paragraph("<b>File</b>", styles["SC_Label"]),
        Paragraph("<b>Line</b>", styles["SC_Label"]),
    ]]
    for item in findings:
        severity = safe_text(item.get("severity", "Unknown"))
        table_data.append([
            Paragraph(safe_text(item.get("rule_id", "---")), styles["SC_Body"]),
            badge(severity, severity),
            Paragraph(safe_text(item.get("category", "General")), styles["SC_Body"]),
            Paragraph(safe_text(item.get("status", "N/A")), styles["SC_Body"]),
            Paragraph(safe_text(item.get("file", item.get("filename", "-"))), styles["SC_Body"]),
            Paragraph(safe_text(item.get("line", "-")), styles["SC_Body"]),
        ])
    if len(table_data) == 1:
        table_data.append([Paragraph("No findings", styles["SC_Body"]), "", "", "", "", ""])
    table = Table(table_data, colWidths=[24 * mm, 24 * mm, 30 * mm, 20 * mm, 57 * mm, 12 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY_COLOR),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(table)
    story.append(PageBreak())
    return story


def create_detailed_findings(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    story: list[Any] = []
    story.append(Paragraph("Detailed Findings", styles["SC_H1"]))
    findings = results.get("findings", []) or []
    if not findings:
        story.append(Paragraph("No findings were detected during analysis.", styles["SC_Body"]))
        story.append(PageBreak())
        return story

    for item in findings:
        severity = safe_text(item.get("severity", "Unknown"))
        header = badge(f"{safe_text(item.get('rule_id', 'TBD'))} — {severity}", severity)
        story.append(header)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(f"<b>{safe_text(item.get('title', 'Untitled Finding'))}</b>", styles["SC_H2"]))

        details = [
            header_table("Rule ID", safe_text(item.get("rule_id", "-"))),
            header_table("Severity", severity),
            header_table("Category", safe_text(item.get("category", "General"))),
            header_table("Affected Algorithm", safe_text(item.get("affected_algorithm", results.get("algorithm", "Unknown")))),
            header_table("Affected File", safe_text(item.get("file", item.get("filename", "-")))),
            header_table("Affected Line", safe_text(item.get("line", "-"))),
        ]
        for block in details:
            story.append(block)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph("<b>Description</b>", styles["SC_Label"]))
        story.append(Paragraph(safe_text(item.get("description", "No description provided.")), styles["SC_Body"]))
        story.append(Paragraph("<b>Potential Security Impact</b>", styles["SC_Label"]))
        story.append(Paragraph(safe_text(item.get("impact", "Not specified.")), styles["SC_Body"]))
        story.append(Paragraph("<b>Technical Explanation</b>", styles["SC_Label"]))
        story.append(Paragraph(safe_text(item.get("technical_explanation", "Not specified.")), styles["SC_Body"]))
        story.append(Paragraph("<b>Research-based Mitigation Recommendation</b>", styles["SC_Label"]))
        story.append(Paragraph(safe_text(item.get("mitigation", "Not specified.")), styles["SC_Body"]))
        references = item.get("references", []) or []
        if references:
            story.append(Paragraph("<b>References</b>", styles["SC_Label"]))
            for ref in references:
                story.append(Paragraph(safe_text(ref), styles["SC_Body"]))
        story.append(Spacer(1, 4 * mm))
    story.append(PageBreak())
    return story


def create_rule_execution_summary(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    story: list[Any] = []
    story.append(Paragraph("Rule Execution Summary", styles["SC_H1"]))
    findings = results.get("findings", []) or []
    if not findings:
        story.append(Paragraph("No rule execution data available.", styles["SC_Body"]))
        story.append(PageBreak())
        return story

    for item in findings:
        status = safe_text(item.get("status", "Unknown")).lower()
        icon = "✓" if status == "passed" else "✗"
        color = "#16A34A" if status == "passed" else "#DC2626"
        story.append(
            Paragraph(
                f"<font color='{color}'><b>{icon}</b></font> {safe_text(item.get('rule_id', '---'))} — {safe_text(item.get('status', 'Unknown'))}",
                styles["SC_Body"],
            )
        )
    story.append(PageBreak())
    return story


def create_statistics(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    story: list[Any] = []
    story.append(Paragraph("Statistics", styles["SC_H1"]))
    rules_executed = results.get("rules_executed", len(results.get("findings", []) or []))
    rules_passed = results.get("rules_passed", sum(1 for item in (results.get("findings", []) or []) if item.get("status", "Passed").lower() == "passed"))
    rules_failed = results.get("rules_failed", sum(1 for item in (results.get("findings", []) or []) if item.get("status", "Failed").lower() == "failed"))
    files = safe_text(results.get("files", 0))
    loc = safe_text(results.get("lines_of_code", 0))
    duration = safe_text(results.get("analysis_duration", "N/A"))

    stats = [
        ("Total rules executed", rules_executed),
        ("Passed rules", rules_passed),
        ("Failed rules", rules_failed),
        ("Analysis duration", duration),
        ("Files analysed", files),
        ("Source lines analysed", loc),
    ]
    for label, value in stats:
        story.append(Paragraph(f"<b>{label}</b>", styles["SC_Label"]))
        story.append(Paragraph(safe_text(value), styles["SC_Body"]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("Execution Progress", styles["SC_H2"]))
    total = rules_executed if isinstance(rules_executed, int) and rules_executed > 0 else 1
    passed_val = rules_passed if isinstance(rules_passed, int) else 0
    failed_val = rules_failed if isinstance(rules_failed, int) else 0
    story.append(draw_progress_bar(passed_val, total, "Passed", colors.HexColor("#16A34A")))
    story.append(Spacer(1, 2 * mm))
    story.append(draw_progress_bar(failed_val, total, "Failed", colors.HexColor("#DC2626")))
    story.append(PageBreak())
    return story


def draw_progress_bar(value: int, total: int, label: str, fill_color: Any) -> Drawing:
    ratio = min(max(value / total, 0), 1) if total else 0
    width = 160
    height = 16
    drawing = Drawing(width, height + 12)
    drawing.add(Rect(0, 0, width, height, strokeColor=colors.HexColor("#CBD5E1"), fillColor=colors.HexColor("#F8FAFC"), strokeWidth=1, rx=4, ry=4))
    drawing.add(Rect(0, 0, width * ratio, height, strokeColor=None, fillColor=fill_color, rx=4, ry=4))
    drawing.add(String(0, height + 2, f"{label}: {value} / {total}", fontName="Helvetica", fontSize=9, fillColor=DARK_TEXT))
    return drawing


def create_appendix(results: dict[str, Any]) -> list[Any]:
    styles = get_styles()
    story: list[Any] = []
    story.append(Paragraph("Appendix", styles["SC_H1"]))
    story.append(Paragraph("Analysed Files", styles["SC_H2"]))
    files = results.get("analysed_files", results.get("files_list", [])) or []
    if files:
        for filename in files:
            story.append(Paragraph(safe_text(filename), styles["SC_Body"]))
    else:
        story.append(Paragraph("File list not available.", styles["SC_Body"]))
    story.append(Spacer(1, 4 * mm))

    appendix_data = [
        ("Tool version", safe_text(results.get("tool_version", "1.0"))),
        ("Report generated", safe_text(results.get("analysis_date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))),
        ("Scan configuration", safe_text(results.get("scan_configuration", "Not available"))),
        ("Supported algorithms", safe_text(", ".join(results.get("supported_algorithms", []) or []))),
        ("Supported implementation types", safe_text(", ".join(results.get("supported_implementation_types", []) or []))),
    ]
    for label, value in appendix_data:
        story.append(Paragraph(f"<b>{label}</b>", styles["SC_Label"]))
        story.append(Paragraph(value, styles["SC_Body"]))
    story.append(PageBreak())
    return story


def get_severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Information": 0}
    for finding in findings:
        severity = safe_text(finding.get("severity", "Information")).title()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += 1
    return counts


def generate_scan_report(results: dict[str, Any], filename: str) -> None:
    results = normalize_results(results or {})
    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=25 * mm,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
    )
    story: list[Any] = []
    story.extend(create_cover_page(results))
    story.extend(create_executive_summary(results))
    story.extend(create_project_inspection(results))
    story.extend(create_findings_summary(results))
    story.extend(create_detailed_findings(results))
    story.extend(create_rule_execution_summary(results))
    story.extend(create_statistics(results))
    story.extend(create_appendix(results))

    doc.build(
        story,
        onFirstPage=lambda c, d: _on_page(c, d, results),
        onLaterPages=lambda c, d: _on_page(c, d, results),
    )


if __name__ == "__main__":
    example = {
        "project_name": "m4fstack",
        "client_name": "Client X",
        "algorithm": "ML-KEM / Kyber",
        "security_level": "Unknown ML-KEM Variant",
        "implementation_type": "Masked Implementation",
        "language": "C/C++",
        "build_system": "Not detected",
        "files": 3,
        "source_files": 2,
        "header_files": 1,
        "lines_of_code": 906,
        "overall_risk": "High",
        "confidence": 99,
        "detection_confidence": "96%",
        "rules_executed": 15,
        "rules_passed": 9,
        "rules_failed": 6,
        "analysis_duration": "00:01:25",
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool_version": "1.0",
        "detection_evidence": [
            "KYBER_N detected in poly.h",
            "KYBER_Q detected in poly.c",
            "KYBER_K detected in poly.c",
            "poly_compress() detected in poly.h",
            "poly_decompress() detected in poly.h",
            "ntt() detected in poly.h",
            "invntt() detected in poly.h",
        ],
        "findings": [
            {
                "rule_id": "IMP-001",
                "title": "KYBER_K parameter disclosure",
                "severity": "High",
                "category": "Configuration",
                "status": "Failed",
                "file": "poly.c",
                "line": 42,
                "affected_algorithm": "ML-KEM / Kyber",
                "description": "KYBER_K parameter was detected but not validated against expected values.",
                "impact": "Incorrect parameter values can reduce algorithmic security.",
                "technical_explanation": "Kyber security level depends directly on KYBER_K. The extracted KYBER_K value was missing or malformed.",
                "mitigation": "Ensure KYBER_K is defined with a supported integer value of 2, 3, or 4.",
                "references": ["NIST PQC Kyber specification", "RFC 9420"],
            }
        ],
        "analysed_files": ["poly.c", "poly.h", "main.c"],
        "scan_configuration": "Default ScanCrypt profile",
        "supported_algorithms": ["ML-DSA (Dilithium)", "ML-KEM (Kyber)"],
        "supported_implementation_types": ["Portable C / Reference", "AVX2 Optimized", "ARM Cortex-M / Embedded", "Masked Implementation"],
    }
    generate_scan_report(example, "scancrypt_report_example.pdf")
    print("Generated scancrypt_report_example.pdf")
