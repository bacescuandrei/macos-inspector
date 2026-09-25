from __future__ import annotations

import json
import os
import tempfile
import textwrap
import zlib
from pathlib import Path

from macos_inspector.core.models import ScanResult


A4_WIDTH = 595.28
A4_HEIGHT = 841.89
MARGIN = 48.0
BOTTOM = 54.0
NAVY = (0.09, 0.14, 0.23)
BLUE = (0.15, 0.39, 0.92)
SLATE = (0.28, 0.35, 0.45)
PALE = (0.94, 0.96, 1.0)
WHITE = (1.0, 1.0, 1.0)
ACTIONABLE_STATUSES = {"fail", "review", "match", "unknown"}
MAX_TIMELINE_ROWS = 250
MAX_EVIDENCE_CHARS = 4000


def _pdf_text(value: object) -> str:
    normalized = str(value).replace("\r", " ").replace("\t", " ")
    normalized = "".join(character if character == "\n" or ord(character) >= 32 else " " for character in normalized)
    return normalized.encode("cp1252", "replace").decode("cp1252")


def _literal(value: object) -> bytes:
    escaped = _pdf_text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    return escaped.encode("cp1252")


class PortablePdf:
    """Small dependency-free PDF writer for the portable macOS release."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.pages: list[list[bytes]] = []
        self.y = 0.0
        self.new_page(cover=True)

    @staticmethod
    def _color(color: tuple[float, float, float]) -> str:
        return " ".join(f"{component:.3f}" for component in color)

    def new_page(self, cover: bool = False) -> None:
        self.pages.append([])
        self.y = A4_HEIGHT - MARGIN
        if not cover:
            self.text("macOS Inspector", MARGIN, A4_HEIGHT - 30, 8, "F2", SLATE)
            self.text(f"Scan {self.scan_id}", A4_WIDTH - MARGIN, A4_HEIGHT - 30, 7, "F1", SLATE, align="right")
            self.line(MARGIN, A4_HEIGHT - 38, A4_WIDTH - MARGIN, A4_HEIGHT - 38, (0.80, 0.84, 0.90))
            self.y = A4_HEIGHT - 58

    def ensure(self, required: float) -> None:
        if self.y - required < BOTTOM:
            self.new_page()

    def command(self, value: str) -> None:
        self.pages[-1].append(value.encode("ascii"))

    def text(
        self, value: object, x: float, y: float, size: float = 9.5, font: str = "F1",
        color: tuple[float, float, float] = NAVY, align: str = "left",
    ) -> None:
        content = _literal(value)
        estimated_width = len(_pdf_text(value)) * size * (0.60 if font == "F3" else 0.52)
        if align == "right":
            x -= estimated_width
        self.pages[-1].append(
            f"BT /{font} {size:.2f} Tf {self._color(color)} rg 1 0 0 1 {x:.2f} {y:.2f} Tm (".encode("ascii")
            + content + b") Tj ET"
        )

    def line(self, x1: float, y1: float, x2: float, y2: float, color: tuple[float, float, float]) -> None:
        self.command(f"q {self._color(color)} RG 0.6 w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q")

    def rectangle(
        self, x: float, y: float, width: float, height: float,
        color: tuple[float, float, float], stroke: tuple[float, float, float] | None = None,
    ) -> None:
        operation = "B" if stroke else "f"
        stroke_command = f" {self._color(stroke)} RG" if stroke else ""
        self.command(f"q {self._color(color)} rg{stroke_command} {x:.2f} {y:.2f} {width:.2f} {height:.2f} re {operation} Q")

    def wrapped_lines(self, value: object, size: float, width: float, font: str = "F1") -> list[str]:
        character_width = size * (0.60 if font == "F3" else 0.52)
        limit = max(8, int(width / character_width))
        lines: list[str] = []
        for source_line in _pdf_text(value).splitlines() or [""]:
            lines.extend(textwrap.wrap(
                source_line, width=limit, replace_whitespace=False, drop_whitespace=True,
                break_long_words=True, break_on_hyphens=False,
            ) or [""])
        return lines

    def paragraph(
        self, value: object, size: float = 9.5, color: tuple[float, float, float] = NAVY,
        font: str = "F1", indent: float = 0.0, width: float | None = None, gap: float = 6.0,
    ) -> None:
        available = width or (A4_WIDTH - 2 * MARGIN - indent)
        leading = size * 1.35
        lines = self.wrapped_lines(value, size, available, font)
        for line in lines:
            self.ensure(leading)
            self.text(line, MARGIN + indent, self.y, size, font, color)
            self.y -= leading
        self.y -= gap

    def section(self, title: str) -> None:
        self.ensure(44)
        self.y -= 5
        self.text(title, MARGIN, self.y, 17, "F2", NAVY)
        self.y -= 11
        self.line(MARGIN, self.y, MARGIN + 55, self.y, BLUE)
        self.y -= 18

    def label_value(self, label: str, value: object) -> None:
        self.ensure(24)
        self.text(label.upper(), MARGIN, self.y, 7, "F2", SLATE)
        self.paragraph(value or "Not provided", size=9, indent=112, width=A4_WIDTH - 2 * MARGIN - 112, gap=4)

    def add_footers(self) -> None:
        total = len(self.pages)
        for index, page in enumerate(self.pages, 1):
            page.append(f"q {self._color((0.80, 0.84, 0.90))} RG 0.5 w {MARGIN:.2f} 37 m {A4_WIDTH - MARGIN:.2f} 37 l S Q".encode("ascii"))
            footer = f"macOS Inspector - {self.scan_id}"
            page.append(f"BT /F1 7 Tf {self._color(SLATE)} rg 1 0 0 1 {MARGIN:.2f} 24 Tm (".encode("ascii") + _literal(footer) + b") Tj ET")
            page.append(f"BT /F1 7 Tf {self._color(SLATE)} rg 1 0 0 1 {A4_WIDTH - 92:.2f} 24 Tm (Page {index} of {total}) Tj ET".encode("ascii"))


def _serialize(document: PortablePdf, title: str) -> bytes:
    document.add_footers()
    objects: list[bytes | None] = []

    def reserve() -> int:
        objects.append(None)
        return len(objects)

    def add(value: bytes) -> int:
        objects.append(value)
        return len(objects)

    pages_id = reserve()
    regular_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    bold_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    mono_id = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
    page_ids: list[int] = []
    for commands in document.pages:
        content = b"\n".join(commands) + b"\n"
        compressed = zlib.compress(content, 9)
        content_id = add(f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode("ascii") + compressed + b"\nendstream")
        page_id = add(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {A4_WIDTH:.2f} {A4_HEIGHT:.2f}] ".encode("ascii")
            + f"/Resources << /Font << /F1 {regular_id} 0 R /F2 {bold_id} 0 R /F3 {mono_id} 0 R >> >> ".encode("ascii")
            + f"/Contents {content_id} 0 R >>".encode("ascii")
        )
        page_ids.append(page_id)
    objects[pages_id - 1] = f"<< /Type /Pages /Count {len(page_ids)} /Kids [{' '.join(f'{item} 0 R' for item in page_ids)}] >>".encode("ascii")
    info_id = add(b"<< /Title (" + _literal(title) + b") /Author (macOS Inspector) /Creator (macOS Inspector portable PDF) >>")
    catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii"))

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for identifier, value in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{identifier} 0 obj\n".encode("ascii"))
        output.extend(value or b"<<>>")
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def write_portable_pdf(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    document = PortablePdf(result.metadata.scan_id)

    document.rectangle(0, A4_HEIGHT - 255, A4_WIDTH, 255, NAVY)
    document.text("macOS Inspector", MARGIN, A4_HEIGHT - 104, 30, "F2", WHITE)
    document.text("READ-ONLY SECURITY AND DFIR ASSESSMENT", MARGIN, A4_HEIGHT - 132, 10, "F2", (0.65, 0.78, 1.0))
    index_unavailable = result.assessed_count() == 0
    document.text("N/A" if index_unavailable else str(result.overall_score), MARGIN, A4_HEIGHT - 213, 46, "F2", WHITE)
    index_caption = "RULE OUTCOME INDEX" if index_unavailable else "/ 100 RULE OUTCOME INDEX"
    document.text(index_caption, MARGIN + (105 if index_unavailable else 74), A4_HEIGHT - 203, 10, "F2", WHITE)
    document.y = A4_HEIGHT - 305
    metadata_rows = [
        ("Scan ID", result.metadata.scan_id),
        ("Case reference", result.metadata.case_reference),
        ("Analyst", result.metadata.analyst),
        ("Host", result.metadata.hostname),
        ("Completed", result.metadata.completed_at),
        ("Findings", f"{len(result.findings)} displayed / {result.total_finding_count or len(result.findings)} total"),
    ]
    if result.metadata.target_application:
        metadata_rows.insert(3, ("Target application", result.metadata.target_application))
    for label, value in metadata_rows:
        document.label_value(label, value)

    document.new_page()
    document.section("Executive summary")
    document.paragraph("The rule outcome index summarizes documented rule results. It is not the probability that this Mac is safe or compromised.", color=SLATE)
    document.paragraph("Status availability includes completed Not Applicable checks; it does not measure targets assessed.", color=SLATE)
    if index_unavailable:
        document.paragraph("No assessed findings. N/A is not a passing security result.", color=SLATE)
    if result.category_scores:
        for category in result.category_scores:
            document.ensure(34)
            document.rectangle(MARGIN, document.y - 18, A4_WIDTH - 2 * MARGIN, 28, PALE)
            document.text(category, MARGIN + 10, document.y - 7, 9.5, "F2", NAVY)
            coverage = result.category_coverage.get(category, 100)
            index = result.category_rule_index_label(category)
            document.text(f"Index {index}{'' if index == 'N/A' else '/100'}  |  Status {coverage}%", A4_WIDTH - MARGIN - 10, document.y - 7, 8.5, "F2", BLUE, align="right")
            document.y -= 36
    else:
        document.paragraph("No category rule outcome indexes were generated.")

    if result.metadata.collection_errors:
        document.section("Collection errors")
        for error in result.metadata.collection_errors:
            document.paragraph(f"- {error}")

    actionable = [finding for finding in result.findings if finding.status.lower() in ACTIONABLE_STATUSES]
    document.section("Actionable findings")
    document.paragraph(f"{len(actionable)} actionable finding(s) include detailed evidence below.", color=SLATE)
    for finding in actionable:
        document.ensure(72)
        document.text(f"{finding.finding_id} - {finding.title}", MARGIN, document.y, 11.5, "F2", NAVY)
        document.y -= 17
        document.paragraph(f"{finding.severity.label()} | {finding.status} | {finding.category}", size=8, color=BLUE, font="F2", gap=4)
        document.paragraph(f"Observed: {finding.observed_result}", size=9)
        document.paragraph(f"Recommendation: {finding.recommendation}", size=9)
        if finding.commands_used:
            document.paragraph("Commands: " + "; ".join(finding.commands_used), size=7.2, color=SLATE, font="F3")
        if finding.evidence:
            evidence = json.dumps([item.__dict__ for item in finding.evidence], ensure_ascii=False, indent=2)
            if len(evidence) > MAX_EVIDENCE_CHARS:
                evidence = evidence[:MAX_EVIDENCE_CHARS] + "\n... truncated in PDF; see JSON report"
            document.paragraph(evidence, size=6.7, color=SLATE, font="F3", indent=8)
        document.line(MARGIN, document.y, A4_WIDTH - MARGIN, document.y, (0.86, 0.89, 0.93))
        document.y -= 14

    document.section("All findings")
    for finding in result.findings:
        document.ensure(42)
        document.paragraph(f"{finding.finding_id} - {finding.title}", size=9, font="F2", gap=2)
        document.paragraph(
            f"{finding.status} | {finding.severity.label()} | {finding.category}",
            size=7.5, color=SLATE, gap=8,
        )

    if result.timeline:
        document.section("Timeline")
        events = result.timeline[-MAX_TIMELINE_ROWS:]
        document.paragraph(f"Latest {len(events)} of {len(result.timeline)} normalized event(s).", color=SLATE)
        for event in events:
            timestamp = event.timestamp.replace("+00:00", "Z")
            document.paragraph(
                f"{timestamp} | {event.category} | {event.summary} ({event.finding_id})",
                size=7.5, gap=5,
            )

    payload = _serialize(document, "macOS Inspector report")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".pdf", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise
