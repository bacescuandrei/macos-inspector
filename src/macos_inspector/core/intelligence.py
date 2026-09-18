from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable
from urllib.parse import urlencode, urlparse
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from macos_inspector import __version__
from macos_inspector.core.io import read_json_limited
from macos_inspector.core.storage import SettingsStore, application_data_dir
from macos_inspector.reporters.common import secure_write_text


MAX_JSON_BYTES = 25 * 1024 * 1024
MAX_HTML_BYTES = 8 * 1024 * 1024
MAX_CACHE_BYTES = 32 * 1024 * 1024
EPSS_API = "https://api.first.org/data/v1/epss"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
APPLE_RELEASES = "https://support.apple.com/en-us/100100"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3/files/"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


@dataclass(frozen=True)
class IntelligenceResource:
    payload: object
    provider: str
    url: str
    fetched_at: str
    sha256: str
    cache_status: str
    stale: bool

    def provenance(self) -> dict[str, object]:
        return {
            "provider": self.provider, "url": self.url, "fetched_at": self.fetched_at,
            "sha256": self.sha256, "cache_status": self.cache_status, "stale": self.stale,
            "host_data_transmitted": False,
        }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cache_path(name: str) -> Path:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", name):
        raise ValueError("Invalid intelligence cache name.")
    directory = application_data_dir() / "osint-cache"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    return directory / f"{name}.json"


def _load_cache(name: str, validator: Callable[[object], object]) -> tuple[dict, object] | None:
    path = _cache_path(name)
    try:
        record = read_json_limited(path, MAX_CACHE_BYTES)
        if not isinstance(record, dict) or record.get("schema_version") != 1:
            return None
        payload = validator(record.get("payload"))
        expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        if expected != record.get("sha256"):
            return None
        return record, payload
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _store_cache(name: str, provider: str, url: str, payload: object) -> IntelligenceResource:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    fetched_at = _now().isoformat()
    digest = hashlib.sha256(canonical).hexdigest()
    record = {
        "schema_version": 1, "provider": provider, "url": url, "fetched_at": fetched_at,
        "sha256": digest, "payload": payload,
    }
    secure_write_text(_cache_path(name), json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    return IntelligenceResource(payload, provider, url, fetched_at, digest, "refreshed", False)


def _cached_resource(record: dict, payload: object, hours: int, status: str) -> IntelligenceResource:
    fetched = datetime.fromisoformat(str(record["fetched_at"]).replace("Z", "+00:00"))
    stale = _now() - fetched.astimezone(timezone.utc) > timedelta(hours=hours)
    return IntelligenceResource(
        payload, str(record.get("provider", "unknown")), str(record.get("url", "")),
        fetched.astimezone(timezone.utc).isoformat(), str(record.get("sha256", "")), status, stale,
    )


def _request_bytes(url: str, allowed_hosts: set[str], limit: int, headers: dict[str, str] | None = None) -> bytes:
    requested = urlparse(url)
    if requested.scheme != "https" or requested.hostname not in allowed_hosts:
        raise ValueError("Intelligence source is not allowlisted.")
    request_headers = {
        "Accept": "application/json, text/html;q=0.9",
        "User-Agent": f"macOS-Inspector/{__version__} (privacy-first OSINT)",
        **(headers or {}),
    }
    with urlopen(Request(url, headers=request_headers), timeout=25) as response:
        resolved = urlparse(response.geturl())
        if resolved.scheme != "https" or resolved.hostname not in allowed_hosts:
            raise ValueError("Intelligence source redirected to an untrusted host.")
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > limit:
            raise ValueError("Intelligence response exceeds the size limit.")
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("Intelligence response exceeds the size limit.")
    return body


def fetch_cached_json(
    name: str, provider: str, url: str, allowed_hosts: set[str], validator: Callable[[object], object],
    headers: dict[str, str] | None = None, force: bool = False, cache_hours: int | None = None,
) -> IntelligenceResource:
    hours = cache_hours or int(SettingsStore().load()["cache_hours"])
    cached = _load_cache(name, validator)
    if cached and not force:
        resource = _cached_resource(cached[0], cached[1], hours, "cache")
        if not resource.stale:
            return resource
    try:
        body = _request_bytes(url, allowed_hosts, MAX_JSON_BYTES, headers)
        payload = validator(json.loads(body.decode("utf-8")))
        return _store_cache(name, provider, url, payload)
    except Exception:
        if cached:
            return _cached_resource(cached[0], cached[1], hours, "stale-fallback")
        raise


def validate_epss(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("EPSS response is invalid.")
    data = payload["data"]
    if len(data) > 1_000:
        raise ValueError("EPSS response contains too many entries.")
    for item in data:
        if not isinstance(item, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(item.get("cve", ""))):
            raise ValueError("EPSS response contains an invalid CVE.")
        score = float(item.get("epss", -1))
        percentile = float(item.get("percentile", -1))
        if not 0 <= score <= 1 or not 0 <= percentile <= 1:
            raise ValueError("EPSS score is outside its expected range.")
    return payload


def fetch_epss(cve_ids: list[str], force: bool = False) -> IntelligenceResource:
    identifiers = sorted(set(value for value in cve_ids if re.fullmatch(r"CVE-\d{4}-\d{4,}", value)))[:100]
    if not identifiers:
        raise ValueError("No valid CVE identifiers were supplied to EPSS.")
    url = f"{EPSS_API}?{urlencode({'cve': ','.join(identifiers)})}"
    key = hashlib.sha256(",".join(identifiers).encode()).hexdigest()[:16]
    return fetch_cached_json(f"epss-{key}", "FIRST EPSS", url, {"api.first.org"}, validate_epss, force=force)


def validate_nvd(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("NVD response is invalid.")
    if len(payload["vulnerabilities"]) > 1_000:
        raise ValueError("NVD response contains too many entries.")
    for item in payload["vulnerabilities"]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve.get("id", ""))):
            raise ValueError("NVD response contains an invalid CVE entry.")
    return payload


def fetch_nvd(cve_ids: list[str], force: bool = False) -> IntelligenceResource:
    identifiers = sorted(set(value for value in cve_ids if re.fullmatch(r"CVE-\d{4}-\d{4,}", value)))[:100]
    if not identifiers:
        raise ValueError("No valid CVE identifiers were supplied to NVD.")
    url = f"{NVD_API}?{urlencode({'cveIds': ','.join(identifiers)})}"
    settings = SettingsStore().load()
    api_key = settings["providers"]["nvd"].get("api_key", "")
    headers = {"apiKey": api_key} if api_key else {}
    key = hashlib.sha256(",".join(identifiers).encode()).hexdigest()[:16]
    return fetch_cached_json(f"nvd-{key}", "NIST NVD", url, {"services.nvd.nist.gov"}, validate_nvd, headers=headers, force=force)


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden and data.strip():
            self.parts.append(" ".join(data.split()))


def validate_apple_releases(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("releases"), list):
        raise ValueError("Apple release data is invalid.")
    return payload


def parse_apple_security_releases(html: str) -> dict:
    parser = _VisibleText()
    parser.feed(html)
    text = "\n".join(parser.parts)
    releases: list[dict[str, str]] = []
    pattern = re.compile(r"(macOS\s+(?:Tahoe|Sequoia|Sonoma|Ventura|Monterey|Big Sur)?\s*\d+(?:\.\d+){0,2})", re.IGNORECASE)
    for match in pattern.finditer(text):
        name = " ".join(match.group(1).split())
        version_match = re.search(r"\d+(?:\.\d+){0,2}", name)
        if version_match and not any(item["name"].casefold() == name.casefold() for item in releases):
            releases.append({"name": name, "version": version_match.group(0)})
        if len(releases) >= 20:
            break
    if not releases:
        raise ValueError("No macOS releases were found on Apple's security release page.")
    return {"releases": releases}


def fetch_apple_releases(force: bool = False) -> IntelligenceResource:
    hours = int(SettingsStore().load()["cache_hours"])
    cached = _load_cache("apple-security-releases", validate_apple_releases)
    if cached and not force:
        resource = _cached_resource(cached[0], cached[1], hours, "cache")
        if not resource.stale:
            return resource
    try:
        body = _request_bytes(APPLE_RELEASES, {"support.apple.com"}, MAX_HTML_BYTES, {"Accept": "text/html"})
        payload = parse_apple_security_releases(body.decode("utf-8", errors="replace"))
        return _store_cache("apple-security-releases", "Apple", APPLE_RELEASES, payload)
    except Exception:
        if cached:
            return _cached_resource(cached[0], cached[1], hours, "stale-fallback")
        raise


def clear_intelligence_cache() -> int:
    directory = application_data_dir() / "osint-cache"
    count = 0
    if directory.is_dir():
        for path in directory.glob("*.json"):
            try:
                path.unlink()
                count += 1
            except OSError:
                continue
    return count


def lookup_threatfox(indicator: str) -> dict:
    value = indicator.strip()
    if not value or len(value) > 2_048 or any(ord(char) < 32 for char in value):
        raise ValueError("ThreatFox lookup indicator is invalid.")
    settings = SettingsStore().load()["providers"]["threatfox"]
    if not settings.get("enabled"):
        raise ValueError("ThreatFox is disabled in local settings.")
    auth_key = str(settings.get("auth_key", ""))
    if not auth_key:
        raise ValueError("ThreatFox requires a free Auth-Key in local settings.")
    body = json.dumps({"query": "search_ioc", "search_term": value}).encode()
    request = Request(THREATFOX_API, data=body, method="POST", headers={
        "Accept": "application/json", "Content-Type": "application/json", "Auth-Key": auth_key,
        "User-Agent": f"macOS-Inspector/{__version__} (explicit IOC lookup)",
    })
    with urlopen(request, timeout=20) as response:
        resolved = urlparse(response.geturl())
        if resolved.scheme != "https" or resolved.hostname != "threatfox-api.abuse.ch":
            raise ValueError("ThreatFox redirected to an untrusted host.")
        raw = response.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        raise ValueError("ThreatFox response exceeds the size limit.")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("query_status"), str):
        raise ValueError("ThreatFox returned an invalid response.")
    data = payload.get("data") if isinstance(payload.get("data"), list) else []
    return {"query_status": payload["query_status"], "data": data[:100], "indicator_transmitted": value, "automatic_submission": False}


def _sha256(value: str) -> str:
    digest = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("A valid SHA-256 value is required.")
    return digest


def _validate_reputation_cache(payload: object) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("status"), str):
        raise ValueError("Cached reputation response is invalid.")
    return payload


def _cached_reputation(name: str) -> dict | None:
    cached = _load_cache(name, _validate_reputation_cache)
    if not cached:
        return None
    resource = _cached_resource(cached[0], cached[1], int(SettingsStore().load()["cache_hours"]), "cache")
    if resource.stale:
        return None
    provenance = {**resource.provenance(), "host_data_transmitted": True, "transmitted_fields": ["sha256"]}
    return {**resource.payload, "provenance": provenance}


def _store_reputation(name: str, provider: str, url: str, payload: dict) -> dict:
    resource = _store_cache(name, provider, url, payload)
    provenance = {**resource.provenance(), "host_data_transmitted": True, "transmitted_fields": ["sha256"]}
    return {**payload, "provenance": provenance}


def lookup_virustotal_hash(sha256: str) -> dict:
    digest = _sha256(sha256)
    settings = SettingsStore().load()["providers"]["virustotal"]
    if not settings.get("enabled"):
        raise ValueError("VirusTotal is disabled in local settings.")
    api_key = str(settings.get("api_key", ""))
    if not api_key:
        raise ValueError("VirusTotal requires an API key in local settings.")
    cache_name = f"rep-vt-{digest}"
    cached = _cached_reputation(cache_name)
    if cached:
        return cached
    url = f"{VIRUSTOTAL_API}{digest}"
    request = Request(url, headers={"Accept": "application/json", "x-apikey": api_key, "User-Agent": f"macOS-Inspector/{__version__} (explicit hash lookup)"})
    try:
        with urlopen(request, timeout=20) as response:
            destination = urlparse(response.geturl())
            if destination.scheme != "https" or destination.hostname != "www.virustotal.com":
                raise ValueError("VirusTotal redirected to an untrusted host.")
            raw = response.read(5 * 1024 * 1024 + 1)
    except HTTPError as exc:
        if exc.code == 404:
            destination = urlparse(exc.geturl())
            if destination.scheme != "https" or destination.hostname != "www.virustotal.com":
                raise ValueError("VirusTotal redirected to an untrusted host.") from exc
            return _store_reputation(cache_name, "VirusTotal", url, {"status": "not_found", "provider": "VirusTotal", "sha256": digest})
        raise
    if len(raw) > 5 * 1024 * 1024:
        raise ValueError("VirusTotal response exceeds the size limit.")
    payload = json.loads(raw.decode("utf-8"))
    data = payload.get("data") if isinstance(payload, dict) else None
    attributes = data.get("attributes") if isinstance(data, dict) else None
    if not isinstance(attributes, dict):
        raise ValueError("VirusTotal returned an invalid response.")
    stats = attributes.get("last_analysis_stats", {})
    result = {
        "status": "found", "provider": "VirusTotal", "sha256": digest,
        "type": attributes.get("type_description"),
        "reputation": attributes.get("reputation"),
        "analysis_stats": stats if isinstance(stats, dict) else {},
        "last_analysis_date": attributes.get("last_analysis_date"),
    }
    return _store_reputation(cache_name, "VirusTotal", url, result)


def lookup_malwarebazaar_hash(sha256: str) -> dict:
    digest = _sha256(sha256)
    settings = SettingsStore().load()["providers"]["malwarebazaar"]
    if not settings.get("enabled"):
        raise ValueError("MalwareBazaar is disabled in local settings.")
    auth_key = str(settings.get("auth_key", ""))
    if not auth_key:
        raise ValueError("MalwareBazaar requires a free Auth-Key in local settings.")
    cache_name = f"rep-mb-{digest}"
    cached = _cached_reputation(cache_name)
    if cached:
        return cached
    body = urlencode({"query": "get_info", "hash": digest}).encode("ascii")
    request = Request(MALWAREBAZAAR_API, data=body, method="POST", headers={
        "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": auth_key, "User-Agent": f"macOS-Inspector/{__version__} (explicit hash lookup)",
    })
    with urlopen(request, timeout=20) as response:
        destination = urlparse(response.geturl())
        if destination.scheme != "https" or destination.hostname != "mb-api.abuse.ch":
            raise ValueError("MalwareBazaar redirected to an untrusted host.")
        raw = response.read(5 * 1024 * 1024 + 1)
    if len(raw) > 5 * 1024 * 1024:
        raise ValueError("MalwareBazaar response exceeds the size limit.")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("query_status"), str):
        raise ValueError("MalwareBazaar returned an invalid response.")
    rows = payload.get("data") if isinstance(payload.get("data"), list) else []
    first = rows[0] if rows and isinstance(rows[0], dict) else {}
    result = {
        "status": "found" if payload["query_status"] == "ok" and first else "not_found",
        "provider": "MalwareBazaar", "sha256": digest,
        "signature": first.get("signature"), "file_type": first.get("file_type"),
        "first_seen": first.get("first_seen"), "tags": first.get("tags") if isinstance(first.get("tags"), list) else [],
    }
    return _store_reputation(cache_name, "MalwareBazaar", MALWAREBAZAAR_API, result)


def lookup_hash_reputation(sha256: str) -> dict:
    digest = _sha256(sha256)
    settings = SettingsStore().load()["providers"]
    enabled = [name for name in ("virustotal", "malwarebazaar", "threatfox") if settings.get(name, {}).get("enabled")]
    if not enabled:
        raise ValueError("Enable and configure at least one hash reputation provider first.")
    results = []
    for name in enabled:
        try:
            if name == "virustotal":
                result = lookup_virustotal_hash(digest)
            elif name == "malwarebazaar":
                result = lookup_malwarebazaar_hash(digest)
            else:
                raw = lookup_threatfox(digest)
                result = {
                    "status": "found" if raw.get("query_status") == "ok" and raw.get("data") else "not_found",
                    "provider": "ThreatFox", "sha256": digest, "matches": len(raw.get("data", [])),
                }
        except Exception as exc:
            labels = {"virustotal": "VirusTotal", "malwarebazaar": "MalwareBazaar", "threatfox": "ThreatFox"}
            result = {"status": "error", "provider": labels[name], "sha256": digest, "error": str(exc)}
        results.append(result)
    return {
        "sha256_transmitted": digest, "providers": results,
        "automatic_submission": False, "file_uploaded": False,
        "privacy_note": "Only this SHA-256 value was sent to the explicitly enabled providers.",
    }
