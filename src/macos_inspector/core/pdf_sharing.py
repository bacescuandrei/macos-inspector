"""Reduced PDF sharing summaries built from an explicit field allowlist."""
from __future__ import annotations

import re

from macos_inspector import __version__
from macos_inspector.core.pdf_inspector import INTERESTING_NAMES, MAX_RECORDS, MAX_TOKENS


ACTION_TYPES = ("JavaScript", "Launch", "URI", "SubmitForm", "ImportData", "GoToR", "GoToE", "GoTo", "Named", "Rendition", "RichMediaExecute")
ASSESSMENTS = {"Review features", "Analysis incomplete", "No supported active features found"}
SHARING_WARNING = "This reduced copy omits detailed evidence. It is not anonymization, a safety verdict, or a replacement for the original report. Counts and optional fingerprints can still identify a document. Review the entire preview before sharing."
OMITTED_FIELDS = (
    "Document and attachment names", "Document metadata", "Analysis timestamps and inspection identifiers",
    "Destinations, URLs, and file paths", "JavaScript text, indicators, and script hashes",
    "Raw object context and diagnostic messages", "Document size and detailed structure",
)


def build_pdf_sharing_summary(report: dict, include_hash: bool = False) -> dict:
    """Never copy free-form document text, even into warnings or field labels."""
    if type(include_hash) is not bool:
        raise ValueError("Include document hash must be a boolean.")
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise ValueError("A supported PDF inspection report is required.")
    required = ("file", "structure", "assessment", "name_counts")
    if any(not isinstance(report.get(key), dict) for key in required):
        raise ValueError("The saved PDF report is incomplete.")
    records = {}
    for key in ("actions", "javascript", "destinations", "attachments", "limitations"):
        rows = report.get(key)
        if not isinstance(rows, list) or len(rows) > (100 if key == "limitations" else MAX_RECORDS):
            raise ValueError("The saved PDF report has invalid or oversized evidence records.")
        if key != "limitations" and any(not isinstance(row, dict) for row in rows):
            raise ValueError("The saved PDF report has invalid evidence records.")
        records[key] = rows
    names = {}
    for name in INTERESTING_NAMES:
        count = report["name_counts"].get(name)
        names[name] = count if type(count) is int and 0 <= count <= MAX_TOKENS else None
    action_counts = {name: 0 for name in (*ACTION_TYPES, "Other action type")}
    for row in records["actions"]:
        kind = row.get("type")
        action_counts[kind if isinstance(kind, str) and kind in ACTION_TYPES else "Other action type"] += 1
    label = report["assessment"].get("label")
    known_assessment = isinstance(label, str) and label in ASSESSMENTS
    if not known_assessment:
        label = "Analysis incomplete"
    complete = (
        known_assessment and label != "Analysis incomplete"
        and report["assessment"].get("analysis_complete_within_supported_scope") is True
        and not records["limitations"] and all(count is not None for count in names.values())
    )
    summary = {
        "schema_version": 1, "report_kind": "pdf-sharing-summary", "tool_version": __version__,
        "redaction": {
            "original_evidence_modified": False, "document_hash_included": include_hash,
            "omitted_fields": list(OMITTED_FIELDS) + ([] if include_hash else ["Document SHA-256"]),
            "warning": SHARING_WARNING,
        },
        "assessment": {"label": label, "malware_verdict": "Not determined", "analysis_complete_within_supported_scope": complete},
        "observations": {
            "action_records": len(records["actions"]), "javascript_records": len(records["javascript"]),
            "destination_records": len(records["destinations"]), "attachment_reference_records": len(records["attachments"]),
            "limitation_records": len(records["limitations"]),
        },
        "structural_name_counts": names, "action_type_counts": {name: count for name, count in action_counts.items() if count},
        "boundary": "Recorded counts refer to supported recovered evidence, may include duplicates or superseded revisions, and are not counts of executed behaviors. No code was executed, no pages were rendered, and no destinations were contacted. Missing indicators do not establish safety.",
    }
    if include_hash:
        digest = report["file"].get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("The saved document SHA-256 is invalid.")
        summary["document_sha256"] = digest
    return summary
