from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

from macos_inspector.core.models import ScanResult
from macos_inspector.reporters.portable_pdf import write_portable_pdf


ACTIONABLE_STATUSES = {"fail", "review", "match", "unknown"}
MAX_TIMELINE_ROWS = 250
MAX_EVIDENCE_CHARS = 4000


def write_pdf(result: ScanResult, path: Path) -> None:
    if importlib.util.find_spec("reportlab") is None:
        write_portable_pdf(result, path)
        return

    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        CondPageBreak, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".pdf", dir=path.parent)
    os.close(descriptor)
    temporary_path = Path(temporary)
    try:
        styles = getSampleStyleSheet()
        navy, blue, pale, line = colors.HexColor("#17233b"), colors.HexColor("#2563eb"), colors.HexColor("#edf3ff"), colors.HexColor("#cbd5e1")
        styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=28, leading=33, textColor=navy, alignment=TA_CENTER, spaceAfter=12))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=17, leading=21, textColor=navy, spaceBefore=10, spaceAfter=10))
        styles.add(ParagraphStyle(name="FindingTitle", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=navy, spaceBefore=8, spaceAfter=5))
        styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10, textColor=colors.HexColor("#475569")))
        styles.add(ParagraphStyle(name="TableHeader", parent=styles["Small"], fontName="Helvetica-Bold", textColor=colors.white))
        styles.add(ParagraphStyle(name="CodeSmall", parent=styles["Code"], fontName="Courier", fontSize=6.5, leading=8, backColor=colors.HexColor("#f8fafc"), borderPadding=5))

        def paragraph(value: object, style: str = "BodyText"):
            return Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style])

        def page(canvas, document):
            canvas.saveState()
            canvas.setStrokeColor(line)
            canvas.line(18 * mm, 15 * mm, 192 * mm, 15 * mm)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#64748b"))
            canvas.drawString(18 * mm, 10 * mm, f"macOS Inspector - scan {result.metadata.scan_id}")
            canvas.drawRightString(192 * mm, 10 * mm, f"Page {document.page}")
            canvas.restoreState()

        document = SimpleDocTemplate(
            str(temporary_path), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
            topMargin=18 * mm, bottomMargin=22 * mm, title="macOS Inspector report",
            author="macOS Inspector",
        )
        story = [Spacer(1, 32 * mm), Paragraph("macOS Inspector", styles["CoverTitle"]), paragraph("Read-only security and DFIR assessment", "Heading2"), Spacer(1, 10 * mm)]
        score_rows = [
            [paragraph("RULE OUTCOME INDEX", "Small"), paragraph(result.rule_index_label(), "Heading1")],
            [paragraph("SCAN ID", "Small"), paragraph(result.metadata.scan_id, "Small")],
            [paragraph("CASE REFERENCE", "Small"), paragraph(result.metadata.case_reference or "Not provided", "Small")],
            [paragraph("ANALYST", "Small"), paragraph(result.metadata.analyst or "Not provided", "Small")],
            [paragraph("HOST", "Small"), paragraph(result.metadata.hostname, "Small")],
            [paragraph("COMPLETED", "Small"), paragraph(result.metadata.completed_at, "Small")],
            [paragraph("FINDINGS", "Small"), paragraph(f"{len(result.findings)} displayed / {result.total_finding_count or len(result.findings)} total", "Small")],
        ]
        if result.metadata.target_application:
            score_rows.insert(4, [paragraph("TARGET APPLICATION", "Small"), paragraph(result.metadata.target_application, "Small")])
        score_table = Table(score_rows, colWidths=[42 * mm, 110 * mm])
        score_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), pale), ("BOX", (0, 0), (-1, -1), .5, line),
            ("INNERGRID", (0, 0), (-1, -1), .25, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.extend([
            score_table,
            paragraph("The rule outcome index summarizes documented rule results. It is not the probability that this Mac is safe or compromised.", "Small"),
            paragraph("Status availability counts completed Not Applicable checks; it does not measure how many targets were assessed.", "Small"),
            *([paragraph("No assessed findings. N/A is not a passing security result.", "Small")] if result.assessed_count() == 0 else []),
            PageBreak(), Paragraph("Executive summary", styles["Section"]),
        ])

        category_rows = [[paragraph("Category", "TableHeader"), paragraph("Rule index", "TableHeader"), paragraph("Status availability", "TableHeader")]]
        for category, score in result.category_scores.items():
            category_rows.append([paragraph(category), paragraph(result.category_rule_index_label(category)), paragraph(f"{result.category_coverage.get(category, 100)}%")])
        category_table = Table(category_rows, colWidths=[100 * mm, 25 * mm, 27 * mm], repeatRows=1)
        category_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), .35, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.extend([category_table, Spacer(1, 7 * mm)])

        if result.metadata.collection_errors:
            story.append(Paragraph("Collection errors", styles["Section"]))
            story.extend(paragraph(f"- {error}") for error in result.metadata.collection_errors)

        actionable = [finding for finding in result.findings if finding.status.lower() in ACTIONABLE_STATUSES]
        story.extend([Paragraph("Actionable findings", styles["Section"]), paragraph(f"{len(actionable)} actionable finding(s) include detailed evidence below.")])
        for finding in actionable:
            story.extend([
                Paragraph(f"{escape(finding.finding_id)} - {escape(finding.title)}", styles["FindingTitle"]),
                paragraph(f"{finding.severity.label()} | {finding.status} | {finding.category}", "Small"),
                paragraph(f"Observed: {finding.observed_result}"),
                paragraph(f"Recommendation: {finding.recommendation}"),
            ])
            if finding.commands_used:
                story.extend([
                    paragraph("Commands: " + "; ".join(finding.commands_used), "Small"),
                    Spacer(1, 2 * mm),
                ])
            if finding.evidence:
                evidence = json.dumps([item.__dict__ for item in finding.evidence], ensure_ascii=False, indent=2)
                if len(evidence) > MAX_EVIDENCE_CHARS:
                    evidence = evidence[:MAX_EVIDENCE_CHARS] + "\n... truncated in PDF; see JSON report"
                story.append(paragraph(evidence, "CodeSmall"))
            story.append(Spacer(1, 3 * mm))

        story.append(Paragraph("All findings", styles["Section"]))
        finding_rows = [[
            paragraph("Finding", "TableHeader"), paragraph("Status", "TableHeader"),
            paragraph("Severity", "TableHeader"), paragraph("Category", "TableHeader"),
        ]]
        for finding in result.findings:
            finding_rows.append([
                paragraph(f"{finding.finding_id} - {finding.title}", "Small"),
                paragraph(finding.status, "Small"), paragraph(finding.severity.label(), "Small"),
                paragraph(finding.category, "Small"),
            ])
        finding_table = Table(finding_rows, colWidths=[79 * mm, 20 * mm, 22 * mm, 31 * mm], repeatRows=1)
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            ("GRID", (0, 0), (-1, -1), .3, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(finding_table)

        if result.timeline:
            story.extend([CondPageBreak(55 * mm), Paragraph("Timeline", styles["Section"]), paragraph(f"Latest {min(MAX_TIMELINE_ROWS, len(result.timeline))} of {len(result.timeline)} normalized event(s).")])
            timeline_rows = [[paragraph("Timestamp (UTC)", "TableHeader"), paragraph("Category", "TableHeader"), paragraph("Event", "TableHeader")]]
            for event in result.timeline[-MAX_TIMELINE_ROWS:]:
                timestamp = event.timestamp.replace("+00:00", "Z")
                timeline_rows.append([paragraph(timestamp, "Small"), paragraph(event.category, "Small"), paragraph(f"{event.summary} ({event.finding_id})", "Small")])
            timeline_table = Table(timeline_rows, colWidths=[48 * mm, 38 * mm, 66 * mm], repeatRows=1)
            timeline_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), navy), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), .3, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(timeline_table)

        document.build(story, onFirstPage=page, onLaterPages=page)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise
