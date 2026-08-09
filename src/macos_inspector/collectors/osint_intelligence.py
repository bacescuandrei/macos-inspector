from __future__ import annotations

import json
from typing import Callable
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .base import Collector
from macos_inspector import __version__
from macos_inspector.core.models import Evidence, Finding, Severity


CISA_KEV_FEED = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CISA_KEV_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MAX_FEED_BYTES = 25 * 1024 * 1024
MAX_VULNERABILITIES = 20_000
ALLOWED_FEED_HOSTS = {"raw.githubusercontent.com"}


def fetch_cisa_kev(url: str = CISA_KEV_FEED) -> dict:
    """Fetch the common public catalog without sending host or case data."""
    request = Request(url, headers={
        "Accept": "application/json",
        "User-Agent": f"macOS-Inspector/{__version__} (read-only OSINT enrichment)",
    })
    with urlopen(request, timeout=20) as response:
        resolved = urlparse(response.geturl())
        if resolved.scheme != "https" or resolved.hostname not in ALLOWED_FEED_HOSTS:
            raise ValueError("The OSINT feed redirected to an untrusted host.")
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_FEED_BYTES:
            raise ValueError("The OSINT feed exceeds the size limit.")
        body = response.read(MAX_FEED_BYTES + 1)
    if len(body) > MAX_FEED_BYTES:
        raise ValueError("The OSINT feed exceeds the size limit.")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The OSINT feed did not contain valid UTF-8 JSON.") from exc
    return validate_cisa_kev(payload)


def validate_cisa_kev(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("The CISA KEV payload must be a JSON object.")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > MAX_VULNERABILITIES:
        raise ValueError("The CISA KEV vulnerability list is invalid or too large.")
    if not isinstance(payload.get("catalogVersion"), str) or not isinstance(payload.get("dateReleased"), str):
        raise ValueError("The CISA KEV catalog metadata is incomplete.")
    count = payload.get("count")
    if not isinstance(count, int) or count != len(vulnerabilities):
        raise ValueError("The CISA KEV catalog count does not match its entries.")
    required = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate")
    for entry in vulnerabilities:
        if not isinstance(entry, dict) or any(not isinstance(entry.get(key), str) or not entry[key] for key in required):
            raise ValueError("The CISA KEV catalog contains an incomplete entry.")
    return payload


def apple_kev_entries(payload: dict) -> tuple[dict[str, object], ...]:
    entries = []
    for item in payload["vulnerabilities"]:
        vendor = item["vendorProject"].strip().casefold()
        if vendor != "apple" and not vendor.startswith("apple "):
            continue
        entries.append({
            "cve_id": item["cveID"],
            "product": item["product"],
            "name": item["vulnerabilityName"],
            "date_added": item["dateAdded"],
            "due_date": item["dueDate"],
            "known_ransomware_use": item.get("knownRansomwareCampaignUse", "Unknown"),
            "required_action": item["requiredAction"],
        })
    return tuple(sorted(entries, key=lambda item: (str(item["date_added"]), str(item["cve_id"])), reverse=True))


class OSINTIntelligenceCollector(Collector):
    collector_id = "osint-intelligence"
    title = "Free OSINT threat intelligence"
    description = "Retrieves the public CISA Known Exploited Vulnerabilities catalog and extracts Apple-related context."
    external_network = True
    privacy_note = "Online opt-in: downloads one common public feed; sends no hashes, host details, case data, or files."

    def __init__(self, runner, fetcher: Callable[[], dict] | None = None) -> None:
        super().__init__(runner)
        self.fetcher = fetcher or fetch_cisa_kev

    def collect(self) -> list[Finding]:
        try:
            payload = validate_cisa_kev(self.fetcher())
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            return [self._unavailable("OSINT-CISA-KEV-CATALOG", "CISA KEV catalog", error), self._unavailable(
                "OSINT-CISA-KEV-APPLE", "Apple vulnerabilities in CISA KEV", error,
            )]
        apple_entries = apple_kev_entries(payload)
        return [self._catalog_finding(payload), self._apple_finding(payload, apple_entries)]

    def _catalog_finding(self, payload: dict) -> Finding:
        count = payload["count"]
        return Finding(
            finding_id="OSINT-CISA-KEV-CATALOG", category="Threat Intelligence",
            title="CISA Known Exploited Vulnerabilities catalog", severity=Severity.INFORMATIONAL, status="Observed",
            description="Retrieves catalog metadata from CISA's official GitHub mirror of vulnerabilities known to be exploited in the wild.",
            why_it_matters="Known exploitation provides prioritization context beyond a vulnerability's theoretical severity.",
            what_was_checked=CISA_KEV_FEED,
            expected_result="The public catalog is retrieved and validated without transmitting host or case information.",
            observed_result=f"Validated CISA KEV catalog version {payload['catalogVersion']} with {count} entries, released {payload['dateReleased']}.",
            recommendation="Use KEV status as prioritization context and confirm affected products and versions locally before drawing conclusions.",
            evidence=(Evidence("osint_catalog_metadata", CISA_KEV_FEED, {
                "provider": "CISA", "catalog": "Known Exploited Vulnerabilities",
                "catalog_version": payload["catalogVersion"], "date_released": payload["dateReleased"],
                "entry_count": count, "host_data_transmitted": False,
            }),),
            references=(CISA_KEV_PAGE, "https://github.com/cisagov/kev-data"),
        )

    def _apple_finding(self, payload: dict, entries: tuple[dict[str, object], ...]) -> Finding:
        newest = entries[0]["date_added"] if entries else "none"
        return Finding(
            finding_id="OSINT-CISA-KEV-APPLE", category="Threat Intelligence",
            title="Apple vulnerabilities in CISA KEV", severity=Severity.INFORMATIONAL, status="Observed",
            description="Extracts Apple-related entries from the current CISA KEV catalog as external threat context.",
            why_it_matters="Apple vulnerabilities with confirmed exploitation can help prioritize version and patch review on macOS systems.",
            what_was_checked=CISA_KEV_FEED,
            expected_result="Apple KEV entries are presented as intelligence context, not as proof that this Mac is vulnerable.",
            observed_result=f"The catalog contains {len(entries)} Apple-related KEV entries; newest catalog addition date: {newest}. This does not establish host exposure.",
            recommendation="Compare relevant CVEs with the exact macOS and application versions using vendor advisories before assigning host impact.",
            evidence=(Evidence("apple_kev_entries", CISA_KEV_FEED, {
                "catalog_version": payload["catalogVersion"], "entries": entries,
                "host_vulnerability_inferred": False, "host_data_transmitted": False,
            }),),
            references=(CISA_KEV_PAGE, "https://support.apple.com/en-us/100100"),
        )

    def _unavailable(self, finding_id: str, title: str, error: str) -> Finding:
        return Finding(
            finding_id=finding_id, category="Threat Intelligence", title=title,
            severity=Severity.INFORMATIONAL, status="Unknown",
            description="Attempts an explicit online retrieval of the public CISA KEV catalog.",
            why_it_matters="External intelligence availability affects enrichment only; local evidence collection remains independent.",
            what_was_checked=CISA_KEV_FEED,
            expected_result="The public CISA KEV feed is reachable and schema-valid.",
            observed_result=error,
            recommendation="Check internet access and retry the OSINT section; local audit results remain valid without this enrichment.",
            evidence=(Evidence("osint_access_error", CISA_KEV_FEED, {
                "error": error, "host_data_transmitted": False,
            }),),
            references=(CISA_KEV_PAGE, "https://github.com/cisagov/kev-data"),
        )
