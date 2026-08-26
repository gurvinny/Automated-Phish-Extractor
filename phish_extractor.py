#!/usr/bin/env python3
"""
phish_extractor.py — Phishing Email IOC Extractor & Threat Intelligence Reporter

Ingests raw .eml files, extracts Indicators of Compromise (IOCs), queries
VirusTotal v3 and AbuseIPDB for reputation data, and produces a structured
threat report in Markdown or JSON.

Author : Gurvin Singh
License: MIT
Python : 3.10+
"""

# THOUGHT PROCESS: We use __future__ annotations so that all type hints are
# evaluated lazily.  This lets us write clean Union / Optional syntax on
# Python 3.10+ while staying compatible with 3.9 at import time.
from __future__ import annotations

import argparse
import base64
import email
import email.policy
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import sys
import time
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Third-party imports — only two non-stdlib packages are required:
#   • requests  – HTTP client for threat-intel API calls
#   • dotenv    – secure loading of API keys from a .env file
# ---------------------------------------------------------------------------
try:
    import requests
except ImportError:
    sys.exit(
        "[FATAL] 'requests' is required.  Install with:  pip install requests"
    )

try:
    from dotenv import load_dotenv
except ImportError:
    sys.exit(
        "[FATAL] 'python-dotenv' is required.  Install with:  pip install python-dotenv"
    )

# THOUGHT PROCESS: Loading the .env file as early as possible ensures that
# every downstream module has access to the secrets.  We never hardcode API
# keys — a leaked key in a public repo can be exploited within minutes by
# automated scanners (e.g., TruffleHog, GitGuardian).
load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VT_API_KEY: str | None = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY: str | None = os.getenv("ABUSEIPDB_API_KEY")


def _positive_int_env(name: str, default: int) -> int:
    """Read a positive integer environment variable with a safe fallback."""
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        print(
            f"[WARN] Invalid {name}={os.getenv(name)!r}; using default {default}.",
            file=sys.stderr,
        )
        return default
    return value if value > 0 else default


VT_BASE_URL: str = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"

# THOUGHT PROCESS: A generous but finite timeout prevents the script from
# hanging indefinitely on unresponsive APIs — important in automated
# pipelines and CI/CD where a stuck process wastes resources.
HTTP_TIMEOUT_SECONDS: int = 15
MAX_EML_SIZE_MB: int = _positive_int_env("MAX_EML_SIZE_MB", 25)
MAX_EML_SIZE_BYTES: int = MAX_EML_SIZE_MB * 1024 * 1024


class SecretRedactionFilter(logging.Filter):
    """Redact configured API keys from every log record."""

    def __init__(self, secrets: list[str | None]) -> None:
        super().__init__()
        self._secrets = tuple(secret for secret in secrets if secret)

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        for secret in self._secrets:
            message = message.replace(secret, "[REDACTED]")
        record.msg = message
        record.args = ()
        return True

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log: logging.Logger = logging.getLogger("phish_extractor")
_redaction_filter = SecretRedactionFilter([VT_API_KEY, ABUSEIPDB_API_KEY])
for _handler in logging.getLogger().handlers:
    _handler.addFilter(_redaction_filter)
log.addFilter(_redaction_filter)

DEFAULT_RATE_LIMIT_DELAY_SECONDS: float = 15.0

# Ceiling on how much unresolved-lookup uncertainty can add to the risk score.
# Keeps provider outages from dominating a verdict that should be driven by
# authentication results and confirmed-malicious hits.
MAX_UNCERTAINTY_SCORE: int = 2

# Once this many lookups in a row come back rate-limited, the quota is spent
# and further retries only add wall-clock time; the remaining IOCs are
# returned unresolved instead.
MAX_CONSECUTIVE_RATE_LIMITS: int = 3

# ---------------------------------------------------------------------------
# Regex patterns for IOC extraction
# ---------------------------------------------------------------------------
# THOUGHT PROCESS: We compile patterns once at module level for performance.
# Each pattern is intentionally strict to minimise false positives — noisy
# IOC extraction degrades analyst trust in the tooling.

# Matches http / https / ftp URLs (may contain path, query, fragment).
URL_PATTERN: re.Pattern[str] = re.compile(
    r"https?://[^\s\"'<>\)\]}>]+", re.IGNORECASE
)

# THOUGHT PROCESS: The domain regex deliberately excludes single-label names
# and requires a 2–63 char TLD to avoid matching random words.  This keeps
# the IOC list meaningful for triage.
DOMAIN_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

# Common file extensions that DOMAIN_PATTERN can match as false-positive domains
# (e.g. "login.php", "index.html" in email body text).
_FILE_EXT_RE: re.Pattern[str] = re.compile(
    r"\.(php\d?|s?html?|asp|aspx|cfm|cgi|pl|py|rb|jsp|do"
    r"|js|ts|css|map"
    r"|png|jpe?g|gif|svg|webp|ico|bmp|tiff?"
    r"|pdf|docx?|xlsx?|pptx?|odt|rtf|txt|csv|xml|json|ya?ml|toml"
    r"|zip|gz|tar|rar|7z|exe|dll|msi|dmg|pkg|deb|rpm"
    r"|eml|msg|ics)$",
    re.IGNORECASE,
)

IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# THOUGHT PROCESS: Full IPv6 addresses rarely appear in phishing bodies, but
# they *do* appear in Received headers and authentication results.  Covering
# them ensures completeness for header-based IOC extraction.
# NOTE: the compressed forms must be tried before the "prefix ending in ::"
# form, otherwise the latter matches only the head of an address such as
# 2001:db8::34 and silently reports a *different* address.
IPV6_PATTERN: re.Pattern[str] = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,5}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:(?![0-9a-fA-F:])"
    r"|(?<![0-9a-fA-F:])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)

# ---------------------------------------------------------------------------
# Data classes — typed containers for extracted data
# ---------------------------------------------------------------------------

@dataclass
class EmailHeaders:
    """Parsed envelope and authentication headers from the .eml file."""

    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    date: str = ""
    message_id: str = ""
    return_path: str = ""
    reply_to: str = ""
    received_chain: list[str] = field(default_factory=list)
    # THOUGHT PROCESS: SPF, DKIM and DMARC results are the first-line
    # indicators of spoofing.  A SOC analyst should check these *before*
    # even looking at the body — a "fail" here is a strong signal that
    # the sender is not who they claim to be.
    spf_result: str = "not found"
    dkim_result: str = "not found"
    dmarc_result: str = "not found"


@dataclass
class AttachmentInfo:
    """Metadata for a single email attachment."""

    filename: str
    content_type: str
    size_bytes: int
    # THOUGHT PROCESS: We hash the attachment rather than opening or executing
    # it.  This follows the principle of *safe static analysis*: a hash is a
    # unique fingerprint that can be looked up against threat-intel databases
    # without ever triggering potentially malicious code (macros, shellcode,
    # polyglot exploits, etc.).
    sha256: str


@dataclass
class IOCCollection:
    """Deduplicated sets of IOCs extracted from the email."""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)


@dataclass
class ThreatIntelResult:
    """Reputation data returned by an external API for a single IOC."""

    ioc: str
    source: str  # "VirusTotal" | "AbuseIPDB"
    malicious: bool = False
    detection_ratio: str = ""
    abuse_confidence: int = 0
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    rate_limited: bool = False


@dataclass
class ThreatReport:
    """Top-level container that aggregates every piece of analysis."""

    analysis_timestamp: str = ""
    source_file: str = ""
    headers: EmailHeaders = field(default_factory=EmailHeaders)
    iocs: IOCCollection = field(default_factory=IOCCollection)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    threat_intel: list[ThreatIntelResult] = field(default_factory=list)
    risk_summary: str = "LOW"


# ===================================================================
# 1. EMAIL PARSING
# ===================================================================

def parse_eml(file_path: Path) -> EmailMessage:
    """Read and parse a raw .eml file into an ``EmailMessage`` object.

    Args:
        file_path: Path to the .eml file on disk.

    Returns:
        A parsed ``EmailMessage`` instance.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file cannot be parsed as an RFC-5322 message.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"EML file not found: {file_path}")

    # THOUGHT PROCESS: We use email.policy.default which returns an
    # EmailMessage (modern API) instead of the legacy Message class.
    # The modern API normalises headers and handles encoding edge-cases
    # more reliably — important because phishing emails deliberately use
    # malformed headers to evade naïve parsers.
    # Read at most one byte beyond the configured limit. This avoids loading
    # an attacker-controlled oversized message into memory before rejecting it.
    try:
        with file_path.open("rb") as eml_file:
            raw_bytes = eml_file.read(MAX_EML_SIZE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Unable to read EML file: {file_path}") from exc

    if len(raw_bytes) > MAX_EML_SIZE_BYTES:
        raise ValueError(
            f"EML file exceeds the {MAX_EML_SIZE_MB} MB size limit: {file_path}"
        )

    msg: EmailMessage = email.message_from_bytes(
        raw_bytes, policy=email.policy.default
    )  # type: ignore[assignment]
    log.info("Parsed email: %s", file_path.name)
    return msg


def _safe_header(msg: EmailMessage, name: str) -> str:
    """Read a single header without trusting it to be well-formed.

    ``email.policy.default`` parses structured headers eagerly, and malformed
    input crashes the stdlib parser rather than returning a degraded value —
    a bare ``From: broken@`` raises ``IndexError`` from
    ``_header_value_parser.get_domain``.  Since every input to this tool is
    attacker-controlled by definition, a single malformed header must not be
    able to end the run.  Falling back to the raw undecoded value keeps the
    IOC and reporting paths working on exactly the messages most likely to be
    hostile.

    Args:
        msg: The parsed message.
        name: Header name to read.

    Returns:
        The header value, or the raw source value if structured parsing
        fails, or an empty string if the header is absent or unreadable.
    """
    try:
        value = msg.get(name, "")
        return str(value) if value is not None else ""
    except (IndexError, ValueError, AttributeError, TypeError) as exc:
        log.warning("Malformed %s header; falling back to raw value (%s)", name, exc)
        try:
            raw = msg.get_raw(name) if hasattr(msg, "get_raw") else None
            if raw:
                return str(raw)
            # Last resort: pull the undecoded line straight out of the source.
            for key, val in msg.raw_items():
                if key.lower() == name.lower():
                    return str(val)
        except Exception:  # pragma: no cover - defensive
            pass
        return ""


def _safe_header_all(msg: EmailMessage, name: str) -> list[str]:
    """Read every instance of a repeated header, skipping unparseable ones."""
    values: list[str] = []
    try:
        raw_values = msg.get_all(name, [])
    except (IndexError, ValueError, AttributeError, TypeError) as exc:
        log.warning("Malformed %s header set; skipping (%s)", name, exc)
        return values
    for value in raw_values:
        try:
            values.append(str(value))
        except (IndexError, ValueError, AttributeError, TypeError):
            log.warning("Skipping one malformed %s header", name)
    return values


def extract_headers(msg: EmailMessage) -> EmailHeaders:
    """Pull envelope headers and authentication results from the message.

    Args:
        msg: A parsed ``EmailMessage``.

    Returns:
        An ``EmailHeaders`` dataclass with all relevant fields populated.
    """
    headers = EmailHeaders(
        subject=_safe_header(msg, "Subject"),
        from_addr=_safe_header(msg, "From"),
        to_addr=_safe_header(msg, "To"),
        date=_safe_header(msg, "Date"),
        message_id=_safe_header(msg, "Message-ID"),
        return_path=_safe_header(msg, "Return-Path"),
        reply_to=_safe_header(msg, "Reply-To"),
    )

    # Collect full Received chain (most recent first)
    headers.received_chain = _safe_header_all(msg, "Received")

    # THOUGHT PROCESS: The Authentication-Results header is added by the
    # *receiving* MTA after performing SPF, DKIM and DMARC checks.  Parsing
    # these is critical because:
    #   • SPF verifies that the sending IP is authorised by the domain's
    #     DNS record — a fail means probable spoofing.
    #   • DKIM verifies the cryptographic signature on the message body —
    #     a fail means the content may have been tampered with in transit.
    #   • DMARC ties SPF + DKIM together with a policy (reject/quarantine/
    #     none) — a fail often triggers automatic quarantine.
    auth_results: str = _safe_header(msg, "Authentication-Results")
    headers.spf_result = _extract_auth_result(auth_results, "spf")
    headers.dkim_result = _extract_auth_result(auth_results, "dkim")
    headers.dmarc_result = _extract_auth_result(auth_results, "dmarc")

    log.info(
        "Auth results — SPF: %s | DKIM: %s | DMARC: %s",
        headers.spf_result,
        headers.dkim_result,
        headers.dmarc_result,
    )
    return headers


def _extract_auth_result(auth_header: str, mechanism: str) -> str:
    """Extract the result value for a given authentication mechanism.

    Looks for patterns like ``spf=pass``, ``dkim=fail``, ``dmarc=none``.

    Args:
        auth_header: Full Authentication-Results header value.
        mechanism: One of ``spf``, ``dkim``, or ``dmarc``.

    Returns:
        The result string (e.g. ``"pass"``) or ``"not found"``.
    """
    pattern = re.compile(rf"{mechanism}\s*=\s*(\w+)", re.IGNORECASE)
    match = pattern.search(auth_header)
    return match.group(1).lower() if match else "not found"


def build_header_ioc_blob(msg: EmailMessage, headers: EmailHeaders) -> str:
    """Build a text blob of sender-controlled header values that may hold IOCs.

    Only headers the *sender* influences are scanned.  The Received chain
    describes the receiving infrastructure, so including it in full extracts
    our own mail relays and recipient domain, submits them to third-party
    reputation APIs, and sends the analyst chasing their own hosts.  The
    outermost hop is the exception: it is the closest thing to the sender's
    own relay that the chain records.
    """
    parts: list[str] = [
        headers.from_addr,
        headers.return_path,
        str(msg.get("Reply-To", "")),
        str(msg.get("X-Originating-IP", "")),
        str(msg.get("X-Mailer", "")),
    ]
    if headers.received_chain:
        # Received headers are prepended by each hop, so the *last* entry is
        # the earliest hop — the one nearest the sender.  Even that hop names
        # both sides ("from <sender> by <us> for <recipient>"), so only the
        # "from" clause is kept.
        sender_hop = _sender_clause(headers.received_chain[-1])
        if sender_hop:
            parts.append(sender_hop)
    return "\n".join(part for part in parts if part)


def _sender_clause(received: str) -> str:
    """Return only the sending half of a Received header.

    A Received header records both ends of a hop::

        from mail.evil.example ([198.51.100.42])
            by mx.ourcompany.example with ESMTP id 12345
            for <victim@ourcompany.example>; Wed, 11 Mar 2026 10:00:00 -0400

    Everything from ``by`` onward describes our own infrastructure and the
    recipient.  Extracting it would ship internal hostnames to third-party
    reputation APIs and list them to the analyst as indicators, so this
    truncates at the first ``by`` token.

    Args:
        received: A single raw Received header value.

    Returns:
        The ``from`` clause, or an empty string if there is no sender half.
    """
    head = re.split(r"\bby\b", received, maxsplit=1, flags=re.IGNORECASE)[0]
    return head.strip() if head.strip().lower().startswith("from") else ""


# ===================================================================
# 2. BODY TEXT EXTRACTION
# ===================================================================

def _decode_part(part: EmailMessage) -> str:
    """Decode one MIME part's text, tolerating attacker-chosen charsets.

    ``get_content()`` resolves the declared charset through ``codecs``, so a
    part claiming ``charset="definitely-not-a-charset"`` raises ``LookupError``
    and would abort the whole run.  A hostile sender can therefore hide a
    payload behind a bogus charset, or simply deny service.  When the declared
    charset is unusable the raw bytes are decoded as UTF-8 with replacement,
    which is lossy but keeps URLs and hostnames — the things IOC extraction
    needs — intact.

    Args:
        part: A single MIME part.

    Returns:
        The decoded text, or an empty string if nothing could be recovered.
    """
    try:
        payload = part.get_content()
        return payload if isinstance(payload, str) else ""
    except (LookupError, UnicodeDecodeError, ValueError, AssertionError) as exc:
        log.warning(
            "Undecodable %s part (%s); retrying as UTF-8 with replacement",
            part.get_content_type(),
            exc,
        )
    try:
        raw = part.get_payload(decode=True)
        if isinstance(raw, (bytes, bytearray)):
            return raw.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - defensive
        log.warning("Could not recover part payload: %s", exc)
    return ""


def get_body_text(msg: EmailMessage) -> str:
    """Recursively extract all plain-text and HTML body parts.

    MIME messages can be deeply nested (multipart/mixed → multipart/
    alternative → text/plain + text/html).  We walk the entire tree so
    that no hidden payloads are missed.

    Args:
        msg: A parsed ``EmailMessage``.

    Returns:
        Concatenated body text suitable for IOC extraction.
    """
    # THOUGHT PROCESS: Attackers sometimes embed malicious links only in the
    # HTML part (hidden behind display text like "Click here to verify your
    # account").  Extracting *both* plain and HTML ensures we capture the
    # actual href targets, not just the visible text.
    parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype: str = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                payload = _decode_part(part)
                if payload:
                    parts.append(payload)
    else:
        payload = _decode_part(msg)
        if payload:
            parts.append(payload)

    body = "\n".join(parts)
    log.info("Extracted %d characters of body text.", len(body))
    return body


# ===================================================================
# 3. IOC EXTRACTION
# ===================================================================

def extract_iocs(text: str) -> IOCCollection:
    """Apply regex patterns to the text and return deduplicated IOCs.

    Args:
        text: Raw body text (plain + HTML) from the email.

    Returns:
        An ``IOCCollection`` with unique URLs, domains, and IP addresses.
    """
    # THOUGHT PROCESS: Deduplication (via sets) is critical.  Phishing emails
    # often repeat the same malicious link dozens of times.  Sending duplicate
    # IOCs to paid APIs wastes quota and clutters the final report.
    urls: set[str] = set(URL_PATTERN.findall(text))
    raw_domains: set[str] = set(DOMAIN_PATTERN.findall(text))
    ipv4s: set[str] = set(IPV4_PATTERN.findall(text))
    ipv6s: set[str] = set(IPV6_PATTERN.findall(text))

    # THOUGHT PROCESS: We filter out RFC-1918 private and loopback IPs
    # because they are *internal* and cannot be threat-intel-checked.
    # Sending 192.168.x.x to VirusTotal adds noise and wastes API calls.
    ipv4s = {ip for ip in ipv4s if _is_routable_ipv4(ip)}
    ipv6s = {ip for ip in ipv6s if _is_routable_ipv6(ip)}

    # Drop bare file-extension tokens (e.g. "login.php", "index.html") that
    # DOMAIN_PATTERN can match as domain IOCs when they appear in body text
    # without a preceding scheme.  These are never real hostnames.
    raw_domains = {d for d in raw_domains if not _FILE_EXT_RE.search(d)}

    # Remove domains that are just parts of extracted URLs to avoid double-
    # counting.  We still keep them accessible via the URL list.
    url_hosts: set[str] = set()
    for url in urls:
        match = re.search(r"://([^/:]+)", url)
        if match:
            url_hosts.add(match.group(1).lower())
    filtered_domains: set[str] = raw_domains - url_hosts

    collection = IOCCollection(
        urls=sorted(urls),
        domains=sorted(filtered_domains),
        ipv4_addresses=sorted(ipv4s),
        ipv6_addresses=sorted(ipv6s),
    )
    total = (
        len(collection.urls)
        + len(collection.domains)
        + len(collection.ipv4_addresses)
        + len(collection.ipv6_addresses)
    )
    log.info("Extracted %d unique IOCs.", total)
    return collection


def _is_routable_ipv4(ip_str: str) -> bool:
    """Return True if the IPv4 address is globally routable.

    Args:
        ip_str: Dotted-quad IPv4 string.

    Returns:
        ``True`` if the address is public / routable.
    """
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return addr.is_global
    except ipaddress.AddressValueError:
        return False


def _is_routable_ipv6(ip_str: str) -> bool:
    """Return True if the IPv6 address is globally routable.

    The IPv4 filter above exists so internal addresses are not shipped to
    reputation APIs.  Received chains carry link-local (``fe80::/10``) and
    unique-local hops routinely, so IPv6 needs the same treatment.

    Args:
        ip_str: IPv6 address string, compressed or full.

    Returns:
        ``True`` if the address is public / routable.
    """
    try:
        return ipaddress.IPv6Address(ip_str).is_global
    except ValueError:
        return False


# ===================================================================
# 4. DEFANGING
# ===================================================================

def defang_url(url: str) -> str:
    """Convert a live URL into a safe, non-clickable representation.

    Example::

        https://evil.com/payload  →  hxxps://evil[.]com/payload

    Args:
        url: A fully-qualified URL string.

    Returns:
        The defanged string.
    """
    # THOUGHT PROCESS: Defanging is an industry-standard practice in threat
    # intelligence sharing (see STIX/TAXII conventions).  If an analyst
    # accidentally clicks a raw URL in a report, it could:
    #   1. Alert the attacker that they are being investigated (beacon).
    #   2. Trigger a drive-by download or exploit kit.
    #   3. Fetch a tracking pixel that reveals the analyst's IP.
    # By replacing "http" → "hxxp" and "." → "[.]" we make the indicator
    # inert while keeping it human-readable and searchable.
    defanged: str = url.replace("http", "hxxp", 1)
    # Only defang dots in the netloc portion (before the first '/').
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        return "/".join(parts)
    return defanged.replace(".", "[.]")


def defang_domain(domain: str) -> str:
    """Defang a bare domain name.

    Args:
        domain: e.g. ``"evil.example.com"``

    Returns:
        ``"evil[.]example[.]com"``
    """
    return domain.replace(".", "[.]")


def defang_ip(ip: str) -> str:
    """Defang an IP address for safe reporting.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        Defanged address (dots replaced with ``[.]``).
    """
    return ip.replace(".", "[.]")


def safe_md(text: str | None) -> str:
    """Sanitize text for safe inclusion in a Markdown table.

    Replaces pipe characters and newlines to prevent Markdown injection
    and table layout breakage. Handles None inputs safely.

    Args:
        text: The raw user-controlled string or None.

    Returns:
        A sanitized string safe for Markdown tables.
    """
    if text is None:
        return "None"

    # Replace pipes with the HTML entity equivalent so tables don't break.
    # Replace newlines with spaces so rows don't wrap unexpectedly.
    return str(text).replace("|", "&#124;").replace("\n", " ").replace("\r", "")


# ===================================================================
# 5. ATTACHMENT HANDLING
# ===================================================================

def extract_attachments(msg: EmailMessage) -> list[AttachmentInfo]:
    """Iterate over MIME parts and fingerprint every attachment.

    Args:
        msg: A parsed ``EmailMessage``.

    Returns:
        A list of ``AttachmentInfo`` records with SHA-256 hashes.
    """
    # THOUGHT PROCESS: We NEVER save attachments to disk or attempt to open
    # them.  Instead we hash the raw bytes in memory.  This is a core tenet
    # of safe malware handling — static indicators (hashes) are sufficient
    # for reputation lookups and can be shared freely without risk of
    # accidental execution.  SHA-256 is the industry standard for malware
    # sample identification (used by VirusTotal, MalwareBazaar, MISP, etc.).
    attachments: list[AttachmentInfo] = []

    for part in msg.walk():
        disposition: str | None = part.get_content_disposition()
        if disposition not in ("attachment", "inline"):
            continue

        filename: str = sanitize_attachment_filename(part.get_filename())
        content_type: str = part.get_content_type()

        raw_payload: Any = part.get_payload(decode=True)
        if raw_payload is None:
            continue

        payload_bytes: bytes
        if isinstance(raw_payload, str):
            payload_bytes = raw_payload.encode("utf-8", errors="replace")
        elif isinstance(raw_payload, bytes):
            payload_bytes = raw_payload
        else:
            continue

        sha256_hash: str = hashlib.sha256(payload_bytes).hexdigest()
        size: int = len(payload_bytes)

        attachments.append(
            AttachmentInfo(
                filename=filename,
                content_type=content_type,
                size_bytes=size,
                sha256=sha256_hash,
            )
        )
        log.info(
            "Attachment: %s (%s, %d bytes, SHA256: %s)",
            filename,
            content_type,
            size,
            sha256_hash,
        )

    return attachments


def sanitize_attachment_filename(filename: str | None) -> str:
    """Return a safe display filename without path traversal components."""
    if not filename:
        return "unnamed_attachment"

    cleaned = re.sub(r"[\x00-\x1f\x7f]", "_", str(filename)).strip()
    cleaned = re.split(r"[\\/]", cleaned)[-1]
    if not cleaned or cleaned in {".", ".."}:
        return "unnamed_attachment"
    return cleaned[:255]


# ===================================================================
# 6. THREAT INTELLIGENCE — VirusTotal v3
# ===================================================================

def query_virustotal_url(url: str) -> ThreatIntelResult:
    """Submit a URL to the VirusTotal v3 /urls endpoint.

    The URL is submitted as a base64url-encoded identifier per the VT v3
    spec.  We then read the analysis stats to determine maliciousness.

    Args:
        url: The raw URL to check.

    Returns:
        A ``ThreatIntelResult`` populated with detection stats or an error.
    """
    # THOUGHT PROCESS: VirusTotal aggregates results from 70+ antivirus
    # engines and URL scanners.  A single "malicious" verdict is interesting;
    # 10+ is a very strong signal.  We report the ratio so the analyst can
    # apply their own threshold.
    result = ThreatIntelResult(ioc=url, source="VirusTotal")

    if not VT_API_KEY:
        result.error = "VT_API_KEY not set"
        log.warning("Skipping VT lookup — API key not configured.")
        return result

    url_id: str = (
        base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    )
    endpoint: str = f"{VT_BASE_URL}/urls/{url_id}"

    return _virustotal_get(endpoint, url, result)


def query_virustotal_hash(sha256: str, filename: str) -> ThreatIntelResult:
    """Look up a file hash on VirusTotal v3.

    Args:
        sha256: The SHA-256 hex digest of the file.
        filename: Original filename (used for display only).

    Returns:
        A ``ThreatIntelResult`` with detection data.
    """
    result = ThreatIntelResult(ioc=f"{filename} ({sha256[:16]}…)", source="VirusTotal")

    if not VT_API_KEY:
        result.error = "VT_API_KEY not set"
        return result

    endpoint: str = f"{VT_BASE_URL}/files/{sha256}"
    return _virustotal_get(endpoint, sha256, result)


def query_virustotal_domain(domain: str) -> ThreatIntelResult:
    """Look up a domain on VirusTotal v3.

    Args:
        domain: The domain string to query.

    Returns:
        A ``ThreatIntelResult`` with detection data.
    """
    result = ThreatIntelResult(ioc=domain, source="VirusTotal")

    if not VT_API_KEY:
        result.error = "VT_API_KEY not set"
        return result

    endpoint: str = f"{VT_BASE_URL}/domains/{domain}"
    return _virustotal_get(endpoint, domain, result)


def _virustotal_get(
    endpoint: str, ioc_label: str, result: ThreatIntelResult
) -> ThreatIntelResult:
    """Perform a GET against a VirusTotal v3 endpoint with resilient error handling.

    Args:
        endpoint: Full API URL.
        ioc_label: Human-readable label for log messages.
        result: Pre-initialised result object to populate.

    Returns:
        The same ``result`` object, populated with data or an error.
    """
    # THOUGHT PROCESS: Robust error handling is non-negotiable for API
    # integrations in production SOC tooling.  We handle:
    #   • Timeouts  — the remote server may be slow or down.
    #   • 401/403   — invalid or revoked API key.
    #   • 429       — rate-limit exceeded (VT free tier = 4 req/min).
    #   • 404       — IOC not in the database (not an error per se).
    #   • Generic   — any unexpected failure should not crash the script.
    headers: dict[str, str] = {"x-apikey": VT_API_KEY or ""}

    try:
        resp: requests.Response = requests.get(
            endpoint, headers=headers, timeout=HTTP_TIMEOUT_SECONDS
        )

        if resp.status_code == 401:
            result.error = "Invalid API key (HTTP 401)"
            log.error("VT auth failed for %s", ioc_label)
            return result

        if resp.status_code == 429:
            result.error = "Rate-limited (HTTP 429) — retry later"
            result.rate_limited = True
            log.warning("VT rate-limited on %s", ioc_label)
            return result

        if resp.status_code == 404:
            result.error = "Not found in VirusTotal database"
            log.info("VT 404 for %s", ioc_label)
            return result

        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

        stats: dict[str, int] = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious_count: int = stats.get("malicious", 0)
        total_count: int = sum(stats.values()) if stats else 0

        result.detection_ratio = f"{malicious_count}/{total_count}"
        result.malicious = malicious_count > 0
        result.details = stats

        log.info(
            "VT result for %s: %s detections", ioc_label, result.detection_ratio
        )

    except requests.exceptions.Timeout:
        result.error = f"Request timed out after {HTTP_TIMEOUT_SECONDS}s"
        log.error("VT timeout for %s", ioc_label)
    except requests.exceptions.RequestException as exc:
        result.error = f"Request failed: {exc}"
        log.error("VT request error for %s: %s", ioc_label, exc)

    return result


# ===================================================================
# 7. THREAT INTELLIGENCE — AbuseIPDB
# ===================================================================

def query_abuseipdb(ip: str) -> ThreatIntelResult:
    """Check an IP address against AbuseIPDB.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        A ``ThreatIntelResult`` with the abuse confidence score.
    """
    # THOUGHT PROCESS: AbuseIPDB is a crowd-sourced IP reputation service.
    # The "abuseConfidenceScore" ranges from 0 (benign) to 100 (certainly
    # malicious).  Scores above 75 are commonly used as a blocking threshold
    # in SOC playbooks and SOAR enrichment workflows.
    result = ThreatIntelResult(ioc=ip, source="AbuseIPDB")

    if not ABUSEIPDB_API_KEY:
        result.error = "ABUSEIPDB_API_KEY not set"
        log.warning("Skipping AbuseIPDB lookup — API key not configured.")
        return result

    endpoint: str = f"{ABUSEIPDB_BASE_URL}/check"
    headers: dict[str, str] = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params: dict[str, str | int] = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": "",
    }

    try:
        resp: requests.Response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=HTTP_TIMEOUT_SECONDS,
        )

        if resp.status_code == 401:
            result.error = "Invalid API key (HTTP 401)"
            log.error("AbuseIPDB auth failed for %s", ip)
            return result

        if resp.status_code == 429:
            result.error = "Rate-limited (HTTP 429) — retry later"
            result.rate_limited = True
            log.warning("AbuseIPDB rate-limited on %s", ip)
            return result

        resp.raise_for_status()
        data: dict[str, Any] = resp.json().get("data", {})

        score: int = data.get("abuseConfidenceScore", 0)
        result.abuse_confidence = score
        result.malicious = score >= 75
        result.details = {
            "country": data.get("countryCode", "??"),
            "isp": data.get("isp", "unknown"),
            "domain": data.get("domain", ""),
            "total_reports": data.get("totalReports", 0),
            "usage_type": data.get("usageType", ""),
        }

        log.info(
            "AbuseIPDB result for %s: confidence=%d%%", ip, score
        )

    except requests.exceptions.Timeout:
        result.error = f"Request timed out after {HTTP_TIMEOUT_SECONDS}s"
        log.error("AbuseIPDB timeout for %s", ip)
    except requests.exceptions.RequestException as exc:
        result.error = f"Request failed: {exc}"
        log.error("AbuseIPDB request error for %s: %s", ip, exc)

    return result


# ===================================================================
# 8. ORCHESTRATION — run all threat-intel lookups
# ===================================================================

def enrich_iocs(
    iocs: IOCCollection,
    attachments: list[AttachmentInfo],
    rate_limit_delay: float = DEFAULT_RATE_LIMIT_DELAY_SECONDS,
) -> list[ThreatIntelResult]:
    """Query external APIs for every extracted IOC and attachment hash.

    Args:
        iocs: The deduplicated IOC collection.
        attachments: List of attachment metadata with SHA-256 hashes.

    Returns:
        A list of ``ThreatIntelResult`` objects (one per API call).
    """
    results: list[ThreatIntelResult] = []
    # One budget shared by every lookup in this run, so the retry ladder is
    # paid once rather than once per IOC when the provider quota is spent.
    budget = RateLimitBudget()

    # --- URLs → VirusTotal ---
    for url in iocs.urls:
        log.info("Checking URL with VirusTotal: %s", url)
        results.append(
            _with_rate_limit_backoff(
                query_virustotal_url,
                f"URL {url}",
                url,
                base_delay_seconds=rate_limit_delay,
                budget=budget,
            )
        )

    # --- Domains → VirusTotal ---
    for domain in iocs.domains:
        log.info("Checking domain with VirusTotal: %s", domain)
        results.append(
            _with_rate_limit_backoff(
                query_virustotal_domain,
                f"domain {domain}",
                domain,
                base_delay_seconds=rate_limit_delay,
                budget=budget,
            )
        )

    # --- IPv4 → AbuseIPDB + VirusTotal is IP-aware but AbuseIPDB is
    #     specialised, so we query it for IPs specifically. ---
    for ip in iocs.ipv4_addresses:
        log.info("Checking IPv4 with AbuseIPDB: %s", ip)
        results.append(
            _with_rate_limit_backoff(
                query_abuseipdb,
                f"IPv4 {ip}",
                ip,
                base_delay_seconds=rate_limit_delay,
                budget=budget,
            )
        )

    for ip in iocs.ipv6_addresses:
        log.info("Checking IPv6 with AbuseIPDB: %s", ip)
        results.append(
            _with_rate_limit_backoff(
                query_abuseipdb,
                f"IPv6 {ip}",
                ip,
                base_delay_seconds=rate_limit_delay,
                budget=budget,
            )
        )

    # --- Attachment hashes → VirusTotal ---
    for att in attachments:
        log.info("Checking attachment hash with VirusTotal: %s", att.filename)
        results.append(
            _with_rate_limit_backoff(
                query_virustotal_hash,
                f"attachment {att.filename}",
                att.sha256,
                att.filename,
                base_delay_seconds=rate_limit_delay,
                budget=budget,
            )
        )

    return results


def _is_rate_limited_result(result: ThreatIntelResult) -> bool:
    """Return True when an API result indicates rate limiting.

    This reads the flag the query functions set from the HTTP status code.
    It deliberately does not pattern-match the error text: request failures
    embed the endpoint URL, so a 503 on ``shop429.com`` — or any of the ~1.5%
    of SHA-256 hashes containing "429" — would otherwise be retried as though
    it were a quota error.
    """
    return result.rate_limited


class RateLimitBudget:
    """Tracks consecutive rate-limit responses across a run of lookups.

    Backoff is per-IOC, so without shared state every IOC pays the full
    retry ladder once the provider quota is exhausted.  With a dozen IOCs
    that is many minutes of sleeping to arrive at the same unresolved
    answer.  This lets the first few IOCs establish that the quota is gone,
    after which the rest return immediately.
    """

    def __init__(self, max_consecutive: int = MAX_CONSECUTIVE_RATE_LIMITS) -> None:
        self.max_consecutive = max_consecutive
        self.consecutive = 0

    @property
    def exhausted(self) -> bool:
        return self.consecutive >= self.max_consecutive

    def record(self, rate_limited: bool) -> None:
        self.consecutive = self.consecutive + 1 if rate_limited else 0


def _with_rate_limit_backoff(
    lookup_fn: Callable[..., ThreatIntelResult],
    ioc_label: str,
    *args: Any,
    base_delay_seconds: float = DEFAULT_RATE_LIMIT_DELAY_SECONDS,
    sleep_fn: Callable[[float], None] | None = None,
    jitter_fn: Callable[[float, float], float] | None = None,
    budget: RateLimitBudget | None = None,
) -> ThreatIntelResult:
    """Retry a lookup function when it returns a rate-limited result."""
    sleep = sleep_fn or time.sleep
    jitter = jitter_fn or random.uniform
    result = lookup_fn(*args)

    if budget is not None and budget.exhausted:
        # Quota already proven spent by earlier IOCs — do not sleep again.
        budget.record(_is_rate_limited_result(result))
        return result

    if base_delay_seconds <= 0:
        if budget is not None:
            budget.record(_is_rate_limited_result(result))
        return result

    delays = [base_delay_seconds, base_delay_seconds * 2, base_delay_seconds * 4]
    for attempt, delay in enumerate(delays, start=1):
        if not _is_rate_limited_result(result):
            if budget is not None:
                budget.record(False)
            return result

        sleep_for = delay + jitter(0, delay * 0.1)
        log.warning(
            "%s rate-limited; retrying in %.1fs (attempt %d/%d)",
            ioc_label,
            sleep_for,
            attempt,
            len(delays),
        )
        sleep(sleep_for)
        result = lookup_fn(*args)

    if budget is not None:
        budget.record(_is_rate_limited_result(result))
    return result


# ===================================================================
# 9. RISK SCORING
# ===================================================================

def _addr_domain(value: str) -> str:
    """Return the lowercased domain of the first email address in a header.

    Args:
        value: A raw header value, possibly ``"Name" <user@example.com>``.

    Returns:
        The domain, or an empty string if none is present.
    """
    match = re.search(r"[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", value or "")
    return match.group(1).lower().rstrip(".") if match else ""


def _registrable(domain: str) -> str:
    """Reduce a hostname to its last two labels for a coarse same-org check."""
    parts = [p for p in domain.split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def detect_identity_mismatches(headers: EmailHeaders) -> list[str]:
    """Flag sender-identity inconsistencies that IOC lookups cannot see.

    Business email compromise is the highest-loss phishing category and
    frequently carries **no URL, no attachment and no malicious infrastructure**
    — nothing an IOC feed can score.  What it does carry is a mismatch between
    the identity being claimed and the address that would actually receive a
    reply.  These checks give that class of message a score of its own.

    Args:
        headers: Parsed envelope headers.

    Returns:
        Human-readable descriptions of each mismatch found.
    """
    findings: list[str] = []
    from_domain = _addr_domain(headers.from_addr)
    reply_domain = _addr_domain(headers.reply_to)
    envelope_domain = _addr_domain(headers.return_path)

    if from_domain and reply_domain and _registrable(reply_domain) != _registrable(from_domain):
        findings.append(
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — "
            "a reply would leave the claimed organisation"
        )
    if (
        from_domain
        and envelope_domain
        and _registrable(envelope_domain) != _registrable(from_domain)
    ):
        findings.append(
            f"Envelope sender ({envelope_domain}) differs from From domain ({from_domain}) — "
            "the visible sender is not the sending domain"
        )
    return findings


def calculate_risk(
    headers: EmailHeaders,
    intel: list[ThreatIntelResult],
) -> str:
    """Derive an overall risk level from extracted signals.

    Scoring heuristic (intentionally simple and auditable):
      * SPF/DKIM/DMARC *fail*      → +2 each
      * SPF *softfail*             → +1
      * DMARC *quarantine*         → +1
      * Each malicious VT result   → +3
      * Each AbuseIPDB score ≥ 75  → +3
      * Reply-To / envelope domain mismatch → +2 each
      * API errors (blind spots)   → capped, see below

    Thresholds:  0–2 LOW | 3–5 MEDIUM | 6–9 HIGH | 10+ CRITICAL

    Args:
        headers: Parsed authentication headers.
        intel: All threat-intel results.

    Returns:
        One of ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``.
    """
    # THOUGHT PROCESS: Automated risk scoring helps analysts prioritise their
    # queue — a "CRITICAL" phish gets triaged before a "LOW" one.  We keep
    # the logic transparent (no ML black-box) so it can be audited and tuned.
    score: int = 0

    if headers.spf_result == "fail":
        score += 2
    elif headers.spf_result == "softfail":
        score += 1
    if headers.dkim_result == "fail":
        score += 2
    if headers.dmarc_result == "fail":
        score += 2
    elif headers.dmarc_result == "quarantine":
        score += 1

    # Identity mismatches carry weight on their own, because a BEC message
    # can be entirely free of IOCs and still be the costliest mail of the day.
    score += 2 * len(detect_identity_mismatches(headers))

    for res in intel:
        if res.malicious:
            score += 3

    # THOUGHT PROCESS: unresolved lookups are a mild uncertainty signal, but
    # the penalty must not scale with the number of IOCs.  A missing API key,
    # an exhausted quota or a network outage fails *every* lookup at once, and
    # an unbounded +1 each would push any message — however benign — to
    # CRITICAL purely because the tool could not reach its providers.  The
    # contribution is therefore capped, and a total failure is treated as one
    # signal rather than N.
    errored = sum(1 for res in intel if res.error)
    if errored:
        score += 1 if errored == len(intel) else min(errored, MAX_UNCERTAINTY_SCORE)

    if score <= 2:
        return "LOW"
    if score <= 5:
        return "MEDIUM"
    if score <= 9:
        return "HIGH"
    return "CRITICAL"


# ===================================================================
# 10. REPORT GENERATION
# ===================================================================

def build_report(
    source_file: str,
    headers: EmailHeaders,
    iocs: IOCCollection,
    attachments: list[AttachmentInfo],
    intel: list[ThreatIntelResult],
    risk: str,
) -> ThreatReport:
    """Assemble all analysis artefacts into a single ``ThreatReport``.

    Args:
        source_file: Original .eml filename.
        headers: Parsed headers.
        iocs: Extracted IOCs.
        attachments: Attachment metadata.
        intel: Threat-intel API results.
        risk: Calculated risk level.

    Returns:
        A fully populated ``ThreatReport`` dataclass.
    """
    return ThreatReport(
        analysis_timestamp=datetime.now(timezone.utc).isoformat(),
        source_file=source_file,
        headers=headers,
        iocs=iocs,
        attachments=attachments,
        threat_intel=intel,
        risk_summary=risk,
    )


def report_to_json(report: ThreatReport) -> str:
    """Serialise the report to a pretty-printed JSON string.

    Args:
        report: The complete threat report.

    Returns:
        A JSON-formatted string.
    """
    return json.dumps(asdict(report), indent=2, default=str)


def report_to_markdown(report: ThreatReport) -> str:
    """Render the report as a human-friendly Markdown document.

    Args:
        report: The complete threat report.

    Returns:
        A Markdown-formatted string.
    """
    # THOUGHT PROCESS: Markdown is the de-facto format for SOC wiki pages,
    # Confluence runbooks, and GitHub issue comments.  Generating a clean
    # Markdown report lets analysts paste it directly into their ticketing
    # system without reformatting.
    risk_emoji: dict[str, str] = {
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "HIGH": "🟠",
        "CRITICAL": "🔴",
    }
    r = report  # alias for brevity

    lines: list[str] = [
        "# Phishing Email Analysis Report",
        "",
        f"**Analysis Timestamp:** {r.analysis_timestamp}  ",
        f"**Source File:** `{r.source_file}`  ",
        f"**Risk Level:** {risk_emoji.get(r.risk_summary, '⚪')} **{r.risk_summary}**",
        "",
        "---",
        "",
        "## 1 — Email Headers",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Subject** | {safe_md(r.headers.subject)} |",
        f"| **From** | {safe_md(defang_domain(r.headers.from_addr))} |",
        f"| **To** | {safe_md(r.headers.to_addr)} |",
        f"| **Date** | {safe_md(r.headers.date)} |",
        f"| **Message-ID** | `{safe_md(r.headers.message_id)}` |",
        f"| **Return-Path** | {safe_md(defang_domain(r.headers.return_path))} |",
        "",
        "### Authentication Results",
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| **SPF** | `{r.headers.spf_result}` |",
        f"| **DKIM** | `{r.headers.dkim_result}` |",
        f"| **DMARC** | `{r.headers.dmarc_result}` |",
        "",
    ]

    # Received chain (truncated for readability)
    if r.headers.received_chain:
        lines.append("### Received Chain (most recent first)")
        lines.append("")
        for i, hop in enumerate(r.headers.received_chain[:5], 1):
            # Collapse whitespace for tidier display
            clean = " ".join(hop.split())
            lines.append(f"{i}. `{clean[:120]}{'…' if len(clean) > 120 else ''}`")
        lines.append("")

    # IOCs
    lines.append("---")
    lines.append("")
    lines.append("## 2 — Indicators of Compromise (IOCs)")
    lines.append("")

    if r.iocs.urls:
        lines.append("### URLs")
        lines.append("")
        for url in r.iocs.urls:
            lines.append(f"- `{defang_url(url)}`")
        lines.append("")

    if r.iocs.domains:
        lines.append("### Domains")
        lines.append("")
        for d in r.iocs.domains:
            lines.append(f"- `{defang_domain(d)}`")
        lines.append("")

    if r.iocs.ipv4_addresses:
        lines.append("### IPv4 Addresses")
        lines.append("")
        for ip in r.iocs.ipv4_addresses:
            lines.append(f"- `{defang_ip(ip)}`")
        lines.append("")

    if r.iocs.ipv6_addresses:
        lines.append("### IPv6 Addresses")
        lines.append("")
        for ip in r.iocs.ipv6_addresses:
            lines.append(f"- `{defang_ip(ip)}`")
        lines.append("")

    if not any(
        [r.iocs.urls, r.iocs.domains, r.iocs.ipv4_addresses, r.iocs.ipv6_addresses]
    ):
        lines.append("_No IOCs extracted._")
        lines.append("")

    # Attachments
    lines.append("---")
    lines.append("")
    lines.append("## 3 — Attachments")
    lines.append("")

    if r.attachments:
        lines.append(
            "| Filename | Content-Type | Size (bytes) | SHA-256 |"
        )
        lines.append("|----------|-------------|-------------|---------|")
        for att in r.attachments:
            lines.append(
                f"| {safe_md(att.filename)} | {safe_md(att.content_type)} | "
                f"{att.size_bytes:,} | `{att.sha256}` |"
            )
        lines.append("")
    else:
        lines.append("_No attachments found._")
        lines.append("")

    # Threat Intel
    lines.append("---")
    lines.append("")
    lines.append("## 4 — Threat Intelligence Enrichment")
    lines.append("")

    if r.threat_intel:
        lines.append(
            "| IOC | Source | Malicious | Detection / Score | Error |"
        )
        lines.append(
            "|-----|--------|-----------|-------------------|-------|"
        )
        for ti in r.threat_intel:
            mal_str: str = "**YES**" if ti.malicious else "No"
            det_str: str = (
                ti.detection_ratio
                if ti.detection_ratio
                else (
                    f"Confidence: {ti.abuse_confidence}%"
                    if ti.abuse_confidence
                    else "—"
                )
            )
            ioc_display: str = defang_url(ti.ioc) if "://" in ti.ioc else defang_domain(ti.ioc)
            lines.append(
                f"| `{ioc_display}` | {ti.source} | {mal_str} | "
                f"{det_str} | {ti.error or '—'} |"
            )
        lines.append("")
    else:
        lines.append("_No threat intelligence data collected._")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        f"> **Automated risk assessment: {risk_emoji.get(r.risk_summary, '')} "
        f"{r.risk_summary}** — Review the IOCs and threat-intel data above "
        f"before making a final determination."
    )
    lines.append("")

    return "\n".join(lines)


# ===================================================================
# 11. CLI ENTRY POINT
# ===================================================================

def build_cli() -> argparse.ArgumentParser:
    """Construct the ``argparse`` CLI parser.

    Returns:
        A configured ``ArgumentParser`` instance.
    """
    parser = argparse.ArgumentParser(
        prog="phish_extractor",
        description=textwrap.dedent("""\
            Phishing Email IOC Extractor & Threat Intelligence Reporter.

            Parses a raw .eml file, extracts IOCs, queries VirusTotal and
            AbuseIPDB, and generates a structured threat report.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "eml_file",
        type=Path,
        help="Path to the .eml file to analyse.",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write report to this file (default: stdout).",
    )
    parser.add_argument(
        "--skip-intel",
        action="store_true",
        help="Skip all external API lookups (offline mode).",
    )
    parser.add_argument(
        "--rate-limit-delay",
        type=float,
        default=DEFAULT_RATE_LIMIT_DELAY_SECONDS,
        help=(
            "Base seconds to wait before retrying a rate-limited API call "
            f"(default: {DEFAULT_RATE_LIMIT_DELAY_SECONDS:g})."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


def main() -> None:
    """Top-level orchestration: parse CLI args, run the pipeline, emit output."""
    parser: argparse.ArgumentParser = build_cli()
    args: argparse.Namespace = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # --- 1. Parse ---
    log.info("=== Phish Extractor — starting analysis ===")
    msg: EmailMessage = parse_eml(args.eml_file)

    # --- 2. Extract ---
    headers: EmailHeaders = extract_headers(msg)
    body: str = get_body_text(msg)
    header_blob: str = build_header_ioc_blob(msg, headers)
    iocs: IOCCollection = extract_iocs(body + "\n" + header_blob)
    attachments: list[AttachmentInfo] = extract_attachments(msg)

    # --- 3. Enrich ---
    intel: list[ThreatIntelResult] = []
    if not args.skip_intel:
        intel = enrich_iocs(iocs, attachments, rate_limit_delay=args.rate_limit_delay)
    else:
        log.info("Threat-intel lookups skipped (--skip-intel).")

    # --- 4. Score ---
    risk: str = calculate_risk(headers, intel)
    log.info("Calculated risk level: %s", risk)

    # --- 5. Report ---
    report: ThreatReport = build_report(
        source_file=args.eml_file.name,
        headers=headers,
        iocs=iocs,
        attachments=attachments,
        intel=intel,
        risk=risk,
    )

    if args.format == "json":
        output_text: str = report_to_json(report)
    else:
        output_text = report_to_markdown(report)

    if args.output:
        args.output.write_text(output_text, encoding="utf-8")
        log.info("Report written to %s", args.output)
    else:
        print(output_text)

    log.info("=== Analysis complete ===")


if __name__ == "__main__":
    main()
