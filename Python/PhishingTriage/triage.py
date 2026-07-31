#!/usr/bin/env python3
"""Phishing email triage — parse a .eml, extract indicators, generate a hunt.

    python triage.py suspicious.eml

Takes a saved message, reports what is observable in it, and emits a Defender
Advanced Hunting query built from the indicators it found. It reports
observations. It does not return a verdict — that is the analyst's call, and a
tool that guesses at one trains you to stop reading the evidence.

Two constraints are enforced in code, not just documented:

  * The workstation never fetches an extracted URL. Every outbound request goes
    to a hostname on NETWORK_ALLOWLIST (the reputation APIs) and nowhere else.
    Detonation belongs in a sandbox.
  * Nothing is submitted unless --submit is passed. Lookups are lookups. There
    is no file-upload code path in this tool at all — see the note above
    submit_url_to_urlscan().

Standard library only, deliberately: this has to run on a managed SOC
workstation where `pip install` is a ticket.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime
import email
import email.errors
import email.policy
import email.utils
import hashlib
import html as html_module
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

# ======================================================================
# Constants
# ======================================================================

# The only hostnames this tool is permitted to contact. Enforced in _request().
# An extracted URL can never end up here, which is the point.
NETWORK_ALLOWLIST = frozenset({"www.virustotal.com", "urlscan.io"})

VT_API = "https://www.virustotal.com/api/v3"
URLSCAN_API = "https://urlscan.io/api/v1"

# VirusTotal's free tier is 4 requests/minute, 500/day. One request every 15
# seconds keeps us inside it. Blowing the quota mid-incident is worse than
# waiting.
VT_DEFAULT_RATE_SECONDS = 15.0

HTTP_TIMEOUT = 20

# Microsoft rewrites inbound URLs at delivery. Regional prefixes vary
# (nam01, eur04, apc01...); GCC/GCC High land on the .us host.
SAFELINKS_HOSTS = (
    "safelinks.protection.outlook.com",
    "safelinks.protection.office365.us",
)

PROOFPOINT_V2_HOSTS = ("urldefense.proofpoint.com",)
PROOFPOINT_V3_HOSTS = ("urldefense.com", "urldefense.us")

# Extensions worth calling out by name in the summary. Not a verdict — an
# HTML attachment is the standard credential-harvest and HTML-smuggling
# delivery method, and it is also how half the world sends receipts.
NOTABLE_EXTENSIONS = {
    "html": "HTML attachment — the standard credential-harvest page and HTML-smuggling carrier",
    "htm": "HTML attachment — the standard credential-harvest page and HTML-smuggling carrier",
    "shtml": "HTML attachment — the standard credential-harvest page and HTML-smuggling carrier",
    "svg": "SVG can carry script; it renders in a browser like a page, not an image",
    "iso": "Disk image — mounts on double-click and defeats mark-of-the-web on the contents",
    "img": "Disk image — mounts on double-click and defeats mark-of-the-web on the contents",
    "vhd": "Disk image — mounts on double-click and defeats mark-of-the-web on the contents",
    "lnk": "Shortcut — the target command line is what matters, not the icon",
    "js": "Script — executes via wscript on double-click",
    "jse": "Script — executes via wscript on double-click",
    "vbs": "Script — executes via wscript on double-click",
    "wsf": "Script — executes via wscript on double-click",
    "hta": "HTML application — runs outside the browser sandbox",
    "ps1": "PowerShell script",
    "bat": "Batch script",
    "cmd": "Batch script",
    "scr": "Executable (screensaver)",
    "exe": "Executable",
    "dll": "Library — typically run via rundll32 or a sideloading chain",
    "msi": "Installer",
    "msix": "Installer",
    "appx": "Installer",
    "one": "OneNote file — was the standard macro replacement after macro blocking",
    "xlsm": "Macro-enabled workbook",
    "xlsb": "Binary workbook — macro-carrying and less inspected than .xlsm",
    "docm": "Macro-enabled document",
    "pptm": "Macro-enabled presentation",
    "iqy": "Excel web query — pulls a remote payload on open",
    "slk": "SYLK file — an old but still-working Excel execution path",
}

ARCHIVE_EXTENSIONS = {"zip", "7z", "rar", "gz", "tar", "cab", "ace", "arj", "bz2", "xz"}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?\.[A-Za-z]{2,}")

URL_RE = re.compile(r"""\b(?:https?|ftp)://[^\s<>"'`\\^\[\]{}]+""", re.IGNORECASE)

ANCHOR_RE = re.compile(
    r"""<a\b[^>]*?\bhref\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)[^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)

ATTR_URL_RE = re.compile(
    r"""\b(?:href|src|action|background|formaction)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)""",
    re.IGNORECASE,
)

TAG_RE = re.compile(r"<[^>]+>")

# Trailing punctuation that is nearly always sentence punctuation, not URL.
URL_TRAILING_JUNK = ".,;:!?'\"”’>)"

SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


# ======================================================================
# Data model
# ======================================================================


@dataclass
class Finding:
    """One observation. `why` explains the failure mode it points at."""

    severity: str  # high | medium | info
    title: str
    detail: str
    why: str

    def to_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "title": self.title, "detail": self.detail, "why": self.why}


@dataclass
class Hop:
    index: int  # 0 = most recent (topmost header)
    raw: str
    from_host: str = ""
    by_host: str = ""
    with_proto: str = ""
    timestamp: str = ""
    ips: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "from": self.from_host,
            "by": self.by_host,
            "with": self.with_proto,
            "timestamp": self.timestamp,
            "ips": self.ips,
        }


@dataclass
class ExtractedUrl:
    url: str  # final destination after unwrapping
    original: str  # exactly as it appeared in the message
    domain: str
    sources: List[str] = field(default_factory=list)  # body parts it appeared in
    rewriters: List[str] = field(default_factory=list)  # gateways unwrapped, outermost first
    anchor_text: str = ""

    @property
    def was_rewritten(self) -> bool:
        return bool(self.rewriters)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "domain": self.domain,
            "original": self.original if self.was_rewritten else None,
            "rewritten_by": self.rewriters or None,
            "sources": self.sources,
            "anchor_text": self.anchor_text or None,
        }


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    extension: str
    inline: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "inline": self.inline,
            "note": self.note or None,
        }


@dataclass
class AuthResults:
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    compauth: str = ""
    compauth_reason: str = ""
    dmarc_action: str = ""
    header_from: str = ""
    smtp_mailfrom: str = ""
    raw: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spf": self.spf or None,
            "dkim": self.dkim or None,
            "dmarc": self.dmarc or None,
            "dmarc_action": self.dmarc_action or None,
            "compauth": self.compauth or None,
            "compauth_reason": self.compauth_reason or None,
            "header_from": self.header_from or None,
            "smtp_mailfrom": self.smtp_mailfrom or None,
        }


@dataclass
class Triage:
    source_file: str
    parsed_utc: str
    origin: str = "eml"  # "eml" (full headers) or "csv" (hunting export)
    network_message_id: str = ""
    delivery_action: str = ""
    delivery_location: str = ""
    threat_types: str = ""
    detection_methods: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_display: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: List[str] = field(default_factory=list)
    return_path: str = ""
    to: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    hops: List[Hop] = field(default_factory=list)
    auth: AuthResults = field(default_factory=AuthResults)
    forefront: Dict[str, str] = field(default_factory=dict)
    urls: List[ExtractedUrl] = field(default_factory=list)
    body_addresses: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    enrichment: Dict[str, Any] = field(default_factory=dict)

    # ---- derived -----------------------------------------------------

    @property
    def sender_domains(self) -> List[str]:
        out = []
        for value in [self.from_domain, domain_of_address(self.return_path)] + [
            domain_of_address(a) for a in self.reply_to
        ]:
            if value and value not in out:
                out.append(value)
        return out

    @property
    def url_domains(self) -> List[str]:
        out = []
        for u in self.urls:
            if u.domain and u.domain not in out:
                out.append(u.domain)
        return out

    @property
    def public_ips(self) -> List[str]:
        """Public IPs from the Received chain, oldest hop first.

        Oldest first because the bottom of the chain is where the message
        entered — but see the README: every hop below your own boundary is
        attacker-supplied text and can be fabricated wholesale.
        """
        out: List[str] = []
        for hop in sorted(self.hops, key=lambda h: -h.index):
            for ip in hop.ips:
                if ip not in out and is_public_ip(ip):
                    out.append(ip)
        return out

    @property
    def counts(self) -> Dict[str, int]:
        c = {"high": 0, "medium": 0, "info": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def add(self, severity: str, title: str, detail: str, why: str) -> None:
        self.findings.append(Finding(severity, title, detail, why))

    def to_ioc_dict(self) -> Dict[str, Any]:
        return {
            "tool": "triage.py",
            "version": __version__,
            "source_file": self.source_file,
            "parsed_utc": self.parsed_utc,
            "message": {
                "subject": self.subject,
                "date": self.date,
                "message_id": self.message_id,
            },
            "sender": {
                "display_name": self.from_display,
                "from_address": self.from_address,
                "from_domain": self.from_domain,
                "return_path": self.return_path,
                "reply_to": self.reply_to,
            },
            "recipients": {"to": self.to, "cc": self.cc},
            "authentication": self.auth.to_dict(),
            "microsoft_antispam": self.forefront or None,
            "received_chain": [h.to_dict() for h in self.hops],
            "indicators": {
                "urls": [u.to_dict() for u in self.urls],
                "url_domains": self.url_domains,
                "sender_domains": self.sender_domains,
                "originating_ips": self.public_ips,
                "body_addresses": self.body_addresses,
                "attachment_sha256": [a.sha256 for a in self.attachments],
            },
            "attachments": [a.to_dict() for a in self.attachments],
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
            "enrichment": self.enrichment or None,
        }


# ======================================================================
# Small helpers
# ======================================================================


def utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def domain_of_address(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().strip(">").lower()


def domain_of_url(url: str) -> str:
    try:
        host = urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower()


def registrable_suffix(domain: str) -> str:
    """Last two labels of a domain.

    Not a public-suffix implementation — it gets co.uk wrong on purpose rather
    than shipping a bundled suffix list that goes stale. It is only used to
    soften a comparison, never to decide anything on its own.
    """
    parts = [p for p in domain.lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


# RFC 5737 / RFC 3849 documentation ranges. Python's ipaddress reports these as
# private, which is correct for routing and wrong here: an address in this range
# in a Received chain arrived from outside, and treating it as internal would
# drop it from the originating-IP list. These ranges only ever appear in test
# fixtures and documentation, so the real-world effect of the carve-out is nil.
DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def is_public_ip(value: str) -> bool:
    """Is this an address worth reporting as external?

    Excludes the ranges that mean "inside the perimeter" — RFC 1918, loopback,
    link-local, multicast — so the originating-IP list is not padded out with
    every internal relay in the chain.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if any(ip in net for net in DOCUMENTATION_NETS):
        return True
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


# Things worth breaking up in human-facing output: URLs, bare domains,
# addresses, IPv4. Matched as whole tokens so surrounding prose is left alone —
# an earlier version replaced every "." in the string and turned sentences into
# "this message[.]".
DEFANGABLE_RE = re.compile(
    r"""(?:(?:https?|ftp)://\S+)"""              # URL
    r"""|(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)"""      # IPv4
    r"""|(?:\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+\b)"""   # address
    r"""|(?:\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b)"""  # domain
)


def _defang_token(token: str) -> str:
    # \S+ swallows the sentence punctuation after a URL. Peel it off and put it
    # back, or the summary reads "...?id=9f2a1c[.]".
    tail = ""
    while token and token[-1] in ".,;:!?":
        tail = token[-1] + tail
        token = token[:-1]
    out = token.replace("http://", "hxxp://").replace("https://", "hxxps://")
    out = out.replace("ftp://", "fxp://")
    return out.replace(".", "[.]") + tail


def defang(value: str) -> str:
    """Break URLs/domains/IPs so a ticketing system cannot linkify them.

    Anything a triage summary contains gets pasted into a ticket, and tickets
    get read by people who click. Defang the human-facing output; leave the
    JSON and the KQL alone because those feed machines.
    """
    if not value:
        return value
    return DEFANGABLE_RE.sub(lambda m: _defang_token(m.group(0)), value)


def md_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def truncate(value: str, limit: int = 110) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def dedupe(values: Sequence[str]) -> List[str]:
    seen: List[str] = []
    for v in values:
        if v and v not in seen:
            seen.append(v)
    return seen


# ======================================================================
# Parsing — headers
# ======================================================================


def parse_message_bytes(raw: bytes, label: str = "") -> email.message.Message:
    """Parse raw message bytes.

    policy.default decodes RFC 2047 headers for us. Real phishing is often
    malformed on purpose, so fall back to compat32 rather than refusing the
    file — a message that breaks the strict parser is a message worth looking
    at, not one to skip.
    """
    if raw[:8].startswith(b"\xd0\xcf\x11\xe0"):
        raise SystemExit(
            "%sThis is an Outlook .msg (OLE compound file); triage.py reads .eml.\n"
            "Use Outlook on the web (... > Download), Outlook for Mac (File > Save As), or the\n"
            ".eml that Defender's Download email action produces." % (label + ": " if label else "")
        )
    if raw[:2] == b"PK":
        raise SystemExit(
            "%sThis is a ZIP, not a message. Pass it directly — triage.py opens Defender's\n"
            "password-protected download itself: triage.py download.zip --zip-password ..."
            % (label + ": " if label else "")
        )
    try:
        return email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:
        return email.message_from_bytes(raw, policy=email.policy.compat32)


def load_message(path: str) -> email.message.Message:
    with open(path, "rb") as fh:
        return parse_message_bytes(fh.read(), os.path.basename(path))


def load_zip_messages(path: str, password: Optional[str]) -> List[Tuple[str, bytes]]:
    """Pull the messages out of Defender's password-protected download.

    Defender's Download email / Download file action does not hand you a bare
    .eml. It asks for a justification — which is written to the audit log, so
    write something a reviewer would accept — then a password, and delivers a
    protected ZIP. The protection is there so the archive survives AV on the way
    to your workstation and cannot be opened by accident.

    Python's zipfile only decrypts legacy ZipCrypto. If the archive uses AES,
    stdlib cannot open it at all and there is no way to fix that without a third
    party package, so say so plainly and let the analyst extract it by hand
    rather than failing with a stack trace.
    """
    import zipfile

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise SystemExit("%s is not a readable ZIP: %s" % (path, exc))

    with archive:
        members = [
            info
            for info in archive.infolist()
            if not info.is_dir() and not os.path.basename(info.filename).startswith("._")
        ]
        if not members:
            raise SystemExit("%s is empty." % path)

        if password:
            archive.setpassword(password.encode("utf-8"))

        out: List[Tuple[str, bytes]] = []
        for info in members:
            try:
                out.append((info.filename, archive.read(info)))
            except RuntimeError as exc:
                message = str(exc).lower()
                if "password" in message:
                    raise SystemExit(
                        "%s: wrong or missing password for %s.\n"
                        "Pass --zip-password, or omit it to be prompted without it reaching your "
                        "shell history." % (path, info.filename)
                    )
                raise SystemExit("%s: could not read %s: %s" % (path, info.filename, exc))
            except NotImplementedError:
                raise SystemExit(
                    "%s uses AES encryption, which the standard library cannot decrypt.\n"
                    "Extract it yourself and point triage.py at the .eml:\n"
                    "    unzip %s -d ./extracted\n"
                    "    python3 triage.py ./extracted/" % (path, path)
                )
        return out


def header(msg: email.message.Message, name: str) -> str:
    value = msg.get(name)
    if value is None:
        return ""
    try:
        return str(value).strip()
    except Exception:
        return ""


def header_all(msg: email.message.Message, name: str) -> List[str]:
    out = []
    for value in msg.get_all(name) or []:
        try:
            out.append(str(value).strip())
        except Exception:
            continue
    return out


def parse_addresses(raw: str) -> List[Tuple[str, str]]:
    """(display name, address) pairs. Tolerates the malformed."""
    if not raw:
        return []
    try:
        pairs = email.utils.getaddresses([raw])
    except Exception:
        return [("", m.group(0)) for m in EMAIL_RE.finditer(raw)]
    return [(name.strip(), addr.strip().strip("<>").lower()) for name, addr in pairs if addr or name]


RECEIVED_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:IPv6:)?((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4})\b")


def parse_received(values: Sequence[str]) -> List[Hop]:
    hops: List[Hop] = []
    for index, raw in enumerate(values):
        flat = " ".join(raw.split())
        hop = Hop(index=index, raw=flat)

        m = RECEIVED_FROM_RE.search(flat)
        if m:
            hop.from_host = m.group(1)
        m = RECEIVED_BY_RE.search(flat)
        if m:
            hop.by_host = m.group(1)
        m = RECEIVED_WITH_RE.search(flat)
        if m:
            hop.with_proto = m.group(1)
        if ";" in flat:
            hop.timestamp = flat.rsplit(";", 1)[1].strip()

        for candidate in IPV4_RE.findall(flat):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in hop.ips:
                hop.ips.append(candidate)
        for candidate in IPV6_RE.findall(flat):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in hop.ips:
                hop.ips.append(candidate)

        hops.append(hop)
    return hops


AUTH_MECH_RE = re.compile(r"\b(spf|dkim|dmarc|compauth)\s*=\s*([A-Za-z]+)", re.IGNORECASE)
AUTH_KV_RE = re.compile(r"\b(reason|action|header\.from|smtp\.mailfrom|header\.d)\s*=\s*([^\s;()]+)", re.IGNORECASE)


def parse_auth_results(values: Sequence[str]) -> AuthResults:
    """Read Authentication-Results.

    The topmost header is the one your own boundary wrote; take the first value
    seen for each mechanism and ignore later restatements. Anything a sender
    put in this header themselves is decoration.
    """
    auth = AuthResults(raw=[" ".join(v.split()) for v in values])
    for raw in values:
        flat = " ".join(raw.split())
        for mech, result in AUTH_MECH_RE.findall(flat):
            mech = mech.lower()
            result = result.lower()
            if not getattr(auth, mech, ""):
                setattr(auth, mech, result)
        for key, value in AUTH_KV_RE.findall(flat):
            key = key.lower()
            if key == "reason" and not auth.compauth_reason:
                auth.compauth_reason = value.strip("'\"")
            elif key == "action" and not auth.dmarc_action:
                auth.dmarc_action = value
            elif key == "header.from" and not auth.header_from:
                auth.header_from = value.lower().strip("<>;")
            elif key == "smtp.mailfrom" and not auth.smtp_mailfrom:
                auth.smtp_mailfrom = value.lower().strip("<>;")
    return auth


SCL_MEANING = {
    "-1": "bypassed filtering (safe sender, allow-list, or transport rule)",
    "0": "not spam",
    "1": "not spam",
    "5": "spam",
    "6": "spam",
    "9": "high-confidence spam or phish",
}

CAT_MEANING = {
    "PHSH": "phish",
    "PHISH": "phish",
    "HPHSH": "high-confidence phish",
    "HPHISH": "high-confidence phish",
    "SPM": "spam",
    "HSPM": "high-confidence spam",
    "MALW": "malware",
    "SPOOF": "spoof",
    "DIMP": "domain impersonation",
    "UIMP": "user impersonation",
    "BULK": "bulk",
    "GIMP": "mailbox intelligence impersonation",
    "AMP": "anti-malware",
}


def parse_forefront(msg: email.message.Message) -> Dict[str, str]:
    """X-Forefront-Antispam-Report / X-Microsoft-Antispam — what EOP decided.

    Present on anything that went through Exchange Online Protection. It tells
    you what the filter concluded and, in SFV, whether a rule or allow-list
    overrode it. SFV:SKN on a phish is a finding about your own configuration.
    """
    out: Dict[str, str] = {}
    blob = " ".join(header_all(msg, "X-Forefront-Antispam-Report") + header_all(msg, "X-Microsoft-Antispam"))
    if not blob:
        return out
    for chunk in blob.split(";"):
        if ":" not in chunk:
            continue
        key, _, value = chunk.partition(":")
        key = key.strip().upper()
        value = value.strip()
        if key and value and key in {"CIP", "CTRY", "SCL", "BCL", "CAT", "SFV", "SFTY", "H", "PTR", "SRV", "IPV"}:
            out.setdefault(key, value)
    return out


# ======================================================================
# Parsing — parts, bodies, attachments
# ======================================================================


def iter_leaves(part: email.message.Message) -> Iterator[email.message.Message]:
    """Leaf parts. message/rfc822 is yielded whole rather than descended into."""
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        yield part
        return
    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for sub in payload:
                yield from iter_leaves(sub)
        return
    yield part


def part_text(part: email.message.Message) -> str:
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, AttributeError):
        return payload.decode("utf-8", errors="replace")


def part_bytes(part: email.message.Message) -> bytes:
    ctype = part.get_content_type()
    if ctype == "message/rfc822":
        payload = part.get_payload()
        if isinstance(payload, list) and payload:
            try:
                return payload[0].as_bytes()
            except Exception:
                return b""
        return b""
    try:
        return part.get_payload(decode=True) or b""
    except Exception:
        return b""


def is_body_part(part: email.message.Message) -> bool:
    disposition = str(part.get("Content-Disposition") or "").lower()
    if "attachment" in disposition:
        return False
    if part.get_filename():
        return False
    return part.get_content_type() in ("text/plain", "text/html")


def find_embedded_message(msg: email.message.Message) -> Optional[email.message.Message]:
    """The original message, when what we were handed is a report wrapper.

    Users report phish with the Report Message add-in or by forwarding as an
    attachment. Triaging the wrapper gives you the reporting user's own headers
    and none of the sender's — clean output about the wrong message.
    """
    for part in iter_leaves(msg):
        if part.get_content_type() == "message/rfc822":
            payload = part.get_payload()
            if isinstance(payload, list) and payload:
                return payload[0]
    return None


def extract_attachments(msg: email.message.Message) -> List[Attachment]:
    out: List[Attachment] = []
    for part in iter_leaves(msg):
        if is_body_part(part):
            continue
        raw = part_bytes(part)
        filename = part.get_filename() or ""
        try:
            filename = str(filename)
        except Exception:
            filename = ""
        ctype = part.get_content_type()
        if not raw and not filename:
            continue
        if ctype.startswith("text/") and not filename and "attachment" not in str(
            part.get("Content-Disposition") or ""
        ).lower():
            continue

        extension = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
        disposition = str(part.get("Content-Disposition") or "").lower()

        note = ""
        if extension in NOTABLE_EXTENSIONS:
            note = NOTABLE_EXTENSIONS[extension]
        elif extension in ARCHIVE_EXTENSIONS:
            note = "Archive — contents are not unpacked here; unpack in a sandbox, not on the workstation"
        elif ctype == "message/rfc822":
            note = "Attached message — re-run triage.py against it, or use --unwrap-forwarded"

        out.append(
            Attachment(
                filename=filename or "(no filename)",
                content_type=ctype,
                size=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
                md5=hashlib.md5(raw).hexdigest(),
                extension=extension,
                inline="inline" in disposition,
                note=note,
            )
        )
    return out


# ======================================================================
# URL extraction and gateway unwrapping
# ======================================================================


def clean_url(candidate: str) -> str:
    url = html_module.unescape(candidate.strip().strip("<>\"'"))
    while url and url[-1] in URL_TRAILING_JUNK:
        if url[-1] == ")" and url.count("(") >= url.count(")"):
            break
        url = url[:-1]
    return url


def _host_matches(host: str, suffixes: Sequence[str]) -> bool:
    host = host.lower()
    return any(host == s or host.endswith("." + s) for s in suffixes)


def _unquote_until_url(value: str, rounds: int = 4) -> str:
    """Percent-decode until it looks like a URL.

    Safe Links usually single-encodes, but a link that was already encoded once
    before Microsoft touched it comes out double-encoded. Stop as soon as it
    parses as a URL so a legitimate %20 inside the real destination survives.
    """
    for _ in range(rounds):
        if value.lower().startswith(("http://", "https://", "ftp://")):
            return value
        decoded = urllib.parse.unquote(value)
        if decoded == value:
            return value
        value = decoded
    return value


def unwrap_once(url: str) -> Tuple[str, str]:
    """Peel one gateway rewrite. Returns (url, gateway name) — name "" if none."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url, ""
    host = (parts.hostname or "").lower()

    if _host_matches(host, SAFELINKS_HOSTS):
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        target = (query.get("url") or query.get("Url") or query.get("URL") or [""])[0]
        if target:
            return _unquote_until_url(target), "Microsoft Defender Safe Links"
        return url, ""

    if _host_matches(host, PROOFPOINT_V2_HOSTS):
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        target = (query.get("u") or [""])[0]
        if target:
            # v2 swaps the percent and slash characters out of the encoded URL.
            target = target.replace("-", "%").replace("_", "/")
            return _unquote_until_url(urllib.parse.unquote(target)), "Proofpoint URL Defense v2"
        return url, ""

    if _host_matches(host, PROOFPOINT_V3_HOSTS) and "/v3/__" in url:
        body = url.split("/v3/__", 1)[1]
        target = body.split("__;", 1)[0] if "__;" in body else body.split("__", 1)[0]
        if target:
            # Best effort: v3 stores substituted characters in the base64 blob
            # after the ';'. The destination host is intact either way, which is
            # what triage needs.
            return _unquote_until_url(target), "Proofpoint URL Defense v3 (best effort)"
        return url, ""

    return url, ""


def unwrap_url(url: str, max_depth: int = 5) -> Tuple[str, List[str]]:
    """Fully unwrap nested gateway rewrites. Returns (destination, gateways)."""
    gateways: List[str] = []
    current = url
    for _ in range(max_depth):
        nxt, gateway = unwrap_once(current)
        if not gateway or nxt == current:
            break
        gateways.append(gateway)
        current = nxt
    return current, gateways


def extract_urls(msg: email.message.Message) -> Tuple[List[ExtractedUrl], List[str]]:
    """URLs and mailto addresses from every body part.

    HTML is read with regex, not a parser. That misses obfuscation a browser
    would resolve (entity-encoded hrefs split across attributes, script-built
    links). It is a triage aid, not a renderer — anything that matters gets
    confirmed against EmailUrlInfo, which saw what Defender saw.
    """
    found: List[ExtractedUrl] = []
    addresses: List[str] = []
    by_destination: Dict[str, ExtractedUrl] = {}

    def record(raw: str, source: str, anchor_text: str = "") -> None:
        """One entry per destination. The same link in the plain-text and HTML
        alternatives is one indicator, not three."""
        cleaned = clean_url(raw)
        if not cleaned or not cleaned.lower().startswith(("http://", "https://", "ftp://")):
            return
        destination, gateways = unwrap_url(cleaned)

        existing = by_destination.get(destination)
        if existing is not None:
            if source not in existing.sources:
                existing.sources.append(source)
            if anchor_text and not existing.anchor_text:
                existing.anchor_text = anchor_text
            if gateways and not existing.rewriters:
                existing.rewriters = gateways
                existing.original = cleaned
            return

        entry = ExtractedUrl(
            url=destination,
            original=cleaned,
            domain=domain_of_url(destination),
            sources=[source],
            rewriters=gateways,
            anchor_text=anchor_text,
        )
        by_destination[destination] = entry
        found.append(entry)

    for index, part in enumerate(iter_leaves(msg)):
        if not is_body_part(part):
            continue
        text = part_text(part)
        if not text:
            continue
        source = "%s[%d]" % (part.get_content_type(), index)

        if part.get_content_type() == "text/html":
            anchor_hrefs = set()
            for href_raw, inner in ANCHOR_RE.findall(text):
                href = href_raw.strip("\"'")
                label = html_module.unescape(TAG_RE.sub(" ", inner))
                label = " ".join(label.split())
                if href.lower().startswith("mailto:"):
                    addresses.extend(EMAIL_RE.findall(urllib.parse.unquote(href)))
                    continue
                anchor_hrefs.add(href)
                record(href, source, label)

            for attr_raw in ATTR_URL_RE.findall(text):
                attr = attr_raw.strip("\"'")
                if attr in anchor_hrefs:
                    continue  # already recorded with its label
                if attr.lower().startswith("mailto:"):
                    addresses.extend(EMAIL_RE.findall(urllib.parse.unquote(attr)))
                    continue
                record(attr, source)

            # Bare URLs pasted into HTML without an anchor. Anchors are removed
            # whole first — element and label together. Link *text* is not a
            # link: an anchor reading "portal.contoso.com" that points somewhere
            # else would otherwise put your own domain into the indicator list
            # and into the generated hunting query.
            without_anchors = ANCHOR_RE.sub(" ", text)
            for bare in URL_RE.findall(TAG_RE.sub(" ", without_anchors)):
                record(bare, source)
        else:
            for bare in URL_RE.findall(text):
                record(bare, source)
            addresses.extend(EMAIL_RE.findall(text))

    return found, dedupe([a.lower() for a in addresses])


# ======================================================================
# Spoofing and mismatch checks — string comparison only, no lookups
# ======================================================================


def check_address_mismatches(t: Triage) -> None:
    from_domain = t.from_domain
    return_domain = domain_of_address(t.return_path)
    reply_domains = dedupe([domain_of_address(a) for a in t.reply_to])

    if t.return_path and from_domain and return_domain and return_domain != from_domain:
        aligned = registrable_suffix(return_domain) == registrable_suffix(from_domain)
        t.add(
            "medium" if aligned else "high",
            "Return-Path domain does not match From domain",
            "From is %s, Return-Path (envelope sender) is %s." % (from_domain, return_domain),
            "SPF authenticates the Return-Path, not the From the user sees. A pass here says the "
            "envelope domain authorised the sending IP and says nothing about the From address. "
            "Legitimate bulk mail splits these constantly, so this is only a finding once the "
            "Return-Path domain is one you cannot account for.",
        )

    for reply_domain in reply_domains:
        if not from_domain or reply_domain == from_domain:
            continue
        aligned = registrable_suffix(reply_domain) == registrable_suffix(from_domain)
        t.add(
            "medium" if aligned else "high",
            "Reply-To is on a different domain than From",
            "From is %s, Reply-To is %s." % (from_domain, reply_domain),
            "This is the mechanism of most BEC: the message looks like it came from a known party, "
            "and the reply goes somewhere the attacker controls. Marketing mail does this too, so "
            "the question is whether the Reply-To domain is one that belongs to the sender.",
        )

    if t.reply_to and not reply_domains:
        t.add(
            "info",
            "Reply-To present but unparseable",
            "Raw value: %s" % truncate("; ".join(t.reply_to)),
            "A malformed Reply-To that a client still renders is worth reading by hand.",
        )


def check_display_name(t: Triage) -> None:
    display = t.from_display or ""
    if not display:
        return

    embedded = [a.lower() for a in EMAIL_RE.findall(display)]
    for address in embedded:
        if address != t.from_address:
            t.add(
                "high",
                "Display name contains an email address that is not the sender",
                'Display name reads "%s"; the actual From address is %s.'
                % (truncate(display, 70), t.from_address or "(none)"),
                "Most mail clients show the display name and hide the address, especially on mobile. "
                "Putting a trusted address inside the display name means the recipient sees the "
                "address they expect and never sees the one that will receive their reply.",
            )

    if not embedded:
        # A display name that is a bare domain, e.g. "contoso.com".
        stripped = display.strip().strip('"').lower()
        if re.fullmatch(r"[a-z0-9\-]+(\.[a-z0-9\-]+)+", stripped) and t.from_domain and stripped != t.from_domain:
            t.add(
                "medium",
                "Display name is a domain that is not the sending domain",
                'Display name reads "%s"; the sending domain is %s.' % (stripped, t.from_domain),
                "Same trick as an embedded address, one step subtler — the client renders the "
                "impersonated domain in the position the recipient reads as identity.",
            )


def check_unicode_tricks(t: Triage) -> None:
    """Non-ASCII and punycode in sender identity. Informational by design.

    A non-ASCII display name is normal for most of the world. It is only worth
    a look next to something else — which is why this never scores above info.
    """
    for label, value in (("From domain", t.from_domain), ("display name", t.from_display)):
        if not value:
            continue
        if value.lower().startswith("xn--") or ".xn--" in value.lower():
            t.add(
                "medium",
                "Punycode (IDN) in the %s" % label,
                "%s: %s" % (label, value),
                "xn-- is an internationalised domain. It renders as non-Latin script in the client, "
                "which is how a lookalike domain reaches the recipient looking correct. Decode it "
                "before comparing it to anything.",
            )
        elif any(ord(ch) > 127 for ch in value):
            t.add(
                "info",
                "Non-ASCII characters in the %s" % label,
                "%s: %s" % (label, value),
                "Ordinary for most senders. Only meaningful if the characters are homoglyphs of a "
                "domain you do business with — compare the codepoints, not how it looks.",
            )


def check_anchor_text(t: Triage) -> None:
    for url in t.urls:
        label = url.anchor_text.strip()
        if not label:
            continue
        label_domain = ""
        if label.lower().startswith(("http://", "https://")):
            label_domain = domain_of_url(clean_url(label))
        elif re.fullmatch(r"[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+(/\S*)?", label):
            label_domain = domain_of_url("http://" + label)
        if not label_domain or not url.domain:
            continue
        if registrable_suffix(label_domain) == registrable_suffix(url.domain):
            continue
        t.add(
            "high",
            "Link text shows one domain, the link goes to another",
            'Text reads "%s"; the link resolves to %s.' % (truncate(label, 60), url.url),
            "The recipient reads the text and the client sends them to the href. When the message "
            "was Safe Links-rewritten, hovering shows the wrapper rather than either one, so the "
            "user has no way to see this at all.",
        )


def check_urls(t: Triage) -> None:
    rewritten = [u for u in t.urls if u.was_rewritten]
    if rewritten:
        t.add(
            "info",
            "%d URL(s) were gateway-rewritten and have been unwrapped" % len(rewritten),
            "Gateways seen: %s." % ", ".join(dedupe([g for u in rewritten for g in u.rewriters])),
            "The wrapper is what sits in the mailbox; the destination is what you block, search, "
            "and submit for reputation. Looking up a Safe Link tells you about Microsoft's domain.",
        )

    for url in t.urls:
        if not url.domain:
            continue
        try:
            ipaddress.ip_address(url.domain)
        except ValueError:
            pass
        else:
            t.add(
                "medium",
                "URL points at a bare IP address",
                url.url,
                "No hostname means no certificate that matches anything and no domain to age. "
                "Rare in legitimate mail, common in throwaway infrastructure.",
            )
            continue
        if url.domain.lower().startswith("xn--") or ".xn--" in url.domain.lower():
            t.add(
                "medium",
                "URL host is a punycode (IDN) domain",
                url.url,
                "Renders as non-Latin script in the address bar. Decode before comparing it to a "
                "domain you trust.",
            )
        if "@" in urllib.parse.urlsplit(url.url).netloc:
            t.add(
                "high",
                "URL contains userinfo before the host",
                url.url,
                "Everything before the @ is discarded by the browser. It exists to put a "
                "trusted-looking string where the reader expects the hostname.",
            )


def check_authentication(t: Triage) -> None:
    auth = t.auth
    if not auth.raw:
        if t.origin != "eml":
            return  # the export simply did not include AuthenticationDetails
        t.add(
            "info",
            "No Authentication-Results header",
            "SPF, DKIM and DMARC results are not recorded in this file.",
            "Either the message never crossed a boundary that stamps one, or the header was lost in "
            "export. Nothing can be concluded about authentication from its absence — go to "
            "EmailEvents.AuthenticationDetails for the recorded verdict.",
        )
        return

    if auth.spf in {"fail", "softfail"}:
        t.add(
            "high" if auth.spf == "fail" else "medium",
            "SPF %s" % auth.spf,
            "smtp.mailfrom=%s" % (auth.smtp_mailfrom or "(not recorded)"),
            "The sending IP is not authorised by the envelope domain's SPF record. A hard fail that "
            "was still delivered usually means a transport rule, an allow-list entry, or a "
            "connector overrode the filter — that override is its own finding.",
        )
    if auth.dkim in {"fail", "none"}:
        t.add(
            "medium" if auth.dkim == "fail" else "info",
            "DKIM %s" % auth.dkim,
            "DKIM result recorded as %s." % auth.dkim,
            "A fail means the body or signed headers changed in transit, or the signature was "
            "forged. `none` just means unsigned, which is unremarkable on its own.",
        )
    if auth.dmarc == "fail":
        t.add(
            "high",
            "DMARC fail%s" % (" (action=%s)" % auth.dmarc_action if auth.dmarc_action else ""),
            "header.from=%s" % (auth.header_from or t.from_domain or "(not recorded)"),
            "Neither SPF nor DKIM aligned with the From domain. If the action was not reject or "
            "quarantine, the sending domain's own DMARC policy is p=none and the message was "
            "delivered by policy, not by mistake.",
        )
    if auth.compauth == "fail":
        t.add(
            "high",
            "Composite authentication fail (reason %s)" % (auth.compauth_reason or "not recorded"),
            "Microsoft's own spoof verdict for this message.",
            "compauth is EOP's combined judgement including its spoof-intelligence signals. "
            "Reasons in the 000-classification range mean explicit spoof detection.",
        )

    passed = {auth.spf, auth.dkim, auth.dmarc} & {"pass"}
    identity_findings = [
        f for f in t.findings if "Display name" in f.title or "Reply-To" in f.title or "Link text" in f.title
    ]
    if "pass" in passed and identity_findings:
        t.add(
            "info",
            "Authentication passed, and that is not exculpatory",
            "SPF/DKIM/DMARC results: spf=%s dkim=%s dmarc=%s."
            % (auth.spf or "-", auth.dkim or "-", auth.dmarc or "-"),
            "Authentication proves the message really came from the domain in the From header. It "
            "proves nothing about whether that domain should be trusted. An attacker's own "
            "registered domain passes all three, and so does a compromised vendor's.",
        )


def check_filter_verdict(t: Triage) -> None:
    ff = t.forefront
    if not ff:
        return
    scl = ff.get("SCL", "")
    cat = ff.get("CAT", "").upper()
    sfv = ff.get("SFV", "").upper()

    if cat and cat in CAT_MEANING:
        t.add(
            "info",
            "EOP category: %s (%s)" % (cat, CAT_MEANING[cat]),
            "SCL:%s SFV:%s SFTY:%s" % (scl or "-", sfv or "-", ff.get("SFTY", "-")),
            "This is what Exchange Online Protection concluded at delivery. Useful as a cross-check "
            "against your own reading, and as the answer to 'did the filter see this'.",
        )
    if sfv in {"SKN", "SKA", "SKI", "SKQ"} or scl == "-1":
        t.add(
            "high",
            "Filtering was bypassed for this message (SFV:%s SCL:%s)" % (sfv or "-", scl or "-"),
            "The message skipped spam filtering rather than passing it.",
            "SKN/SKA/SCL:-1 mean an allow-list entry, a mail-flow rule, or a connector told EOP not "
            "to filter. If this message is malicious, that configuration is the finding — it will "
            "let the next one through too. Find the rule before you close the ticket.",
        )
    elif scl in SCL_MEANING and scl not in {"0", "1"}:
        t.add(
            "info",
            "Spam confidence level %s — %s" % (scl, SCL_MEANING[scl]),
            "X-Forefront-Antispam-Report SCL:%s" % scl,
            "EOP's numeric confidence. Recorded here so the ticket shows what the filter thought.",
        )


def check_routing(t: Triage) -> None:
    if not t.hops:
        t.add(
            "info",
            "No Received headers",
            "The chain is empty.",
            "Either the file was exported without them or the message never transited SMTP. You "
            "cannot establish an originating IP from this file.",
        )
        return

    public = t.public_ips
    if public:
        t.add(
            "info",
            "Originating IP (earliest public hop): %s" % public[0],
            "All public IPs in the chain, oldest first: %s." % ", ".join(public),
            "Received headers are prepended by each hop, so the bottom of the chain is the oldest. "
            "Everything below your own boundary was written by systems you do not control and can "
            "be fabricated wholesale — treat the earliest hop as a lead, and confirm it against "
            "EmailEvents.SenderIPv4 before you put it in a report.",
        )

    message_domain = domain_of_address(t.message_id.strip("<>"))
    if message_domain and t.from_domain and registrable_suffix(message_domain) != registrable_suffix(t.from_domain):
        t.add(
            "info",
            "Message-ID domain does not match the From domain",
            "Message-ID is on %s, From is on %s." % (message_domain, t.from_domain),
            "Weak on its own — plenty of legitimate senders relay through a service that stamps its "
            "own Message-ID. It corroborates, it does not establish.",
        )


def check_attachments(t: Triage) -> None:
    for att in t.attachments:
        if att.extension in NOTABLE_EXTENSIONS:
            t.add(
                "medium",
                "Attachment of note: %s" % att.filename,
                "%s, %d bytes, SHA256 %s" % (att.content_type, att.size, att.sha256),
                NOTABLE_EXTENSIONS[att.extension] + ". Look the hash up; do not open it here.",
            )
        # "invoice.pdf.html" — the client shows the icon for the last extension
        # and plenty of users read the first one.
        base = att.filename.rsplit(".", 1)[0] if "." in att.filename else att.filename
        if "." in base:
            inner = base.rsplit(".", 1)[1].lower()
            if inner in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"}:
                t.add(
                    "high",
                    "Double extension: %s" % att.filename,
                    "Reads as .%s, is actually .%s." % (inner, att.extension or "?"),
                    "Only the final extension decides what opens it. The first one is there to be "
                    "read by a person.",
                )


def check_delivery(t: Triage) -> None:
    """Where a hunting-export row actually landed.

    Only meaningful for CSV input; a .eml on disk says nothing about delivery.
    The combination that matters is a threat verdict next to a delivered
    status — the filter recognised it and it reached the mailbox anyway.
    """
    action = (t.delivery_action or "").lower()
    location = t.delivery_location or ""
    threat = t.threat_types or ""

    if action == "delivered" and threat:
        t.add(
            "high",
            "Delivered despite a threat verdict (%s)" % threat,
            "DeliveryAction=%s, DeliveryLocation=%s, DetectionMethods=%s"
            % (t.delivery_action, location or "-", t.detection_methods or "-"),
            "The filter classified this and it reached the mailbox anyway. Either the verdict "
            "landed after delivery via ZAP, or an override let it through. Check for a mail-flow "
            "rule or allow-list entry — whatever let this one in is still in place.",
        )
    elif action == "delivered" and location.lower() in {"inbox", "inbox/folder"}:
        t.add(
            "medium",
            "Delivered to the inbox",
            "DeliveryLocation=%s" % location,
            "Still sitting in front of the user unless it has been purged. Confirm current "
            "location in Threat Explorer before assuming remediation happened.",
        )
    elif action in {"blocked", "replaced"}:
        t.add(
            "info",
            "Blocked at delivery (%s)" % t.delivery_action,
            "DeliveryLocation=%s, ThreatTypes=%s" % (location or "-", threat or "-"),
            "Recorded so the ticket reflects that this copy did not reach a mailbox. Other copies "
            "in the same campaign may have landed differently — check the delivery breakdown.",
        )


def run_checks(t: Triage) -> None:
    from_eml = t.origin == "eml"

    check_address_mismatches(t)
    check_unicode_tricks(t)
    check_urls(t)
    check_authentication(t)

    # These read the raw message. A hunting export has no display name, no
    # anchor text, no Received chain and no attachment filenames, so running
    # them against CSV rows would report absence as a finding.
    if from_eml:
        check_display_name(t)
        check_anchor_text(t)
        check_filter_verdict(t)
        check_routing(t)
        check_attachments(t)
    else:
        check_delivery(t)

    t.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))


# ======================================================================
# Triage assembly
# ======================================================================


def triage_message(msg: email.message.Message, source_file: str) -> Triage:
    t = Triage(source_file=os.path.basename(source_file), parsed_utc=utcnow())

    t.subject = header(msg, "Subject")
    t.date = header(msg, "Date")
    t.message_id = header(msg, "Message-ID")

    from_pairs = parse_addresses(header(msg, "From"))
    if from_pairs:
        t.from_display, t.from_address = from_pairs[0]
        t.from_domain = domain_of_address(t.from_address)

    t.reply_to = [addr for _, addr in parse_addresses(header(msg, "Reply-To")) if addr]
    return_pairs = parse_addresses(header(msg, "Return-Path"))
    t.return_path = return_pairs[0][1] if return_pairs else ""
    t.to = [addr for _, addr in parse_addresses(header(msg, "To")) if addr]
    t.cc = [addr for _, addr in parse_addresses(header(msg, "Cc")) if addr]

    t.hops = parse_received(header_all(msg, "Received"))
    auth_headers = header_all(msg, "Authentication-Results") + header_all(msg, "ARC-Authentication-Results")
    t.auth = parse_auth_results(auth_headers)
    if not t.auth.smtp_mailfrom:
        spf_header = header(msg, "Received-SPF")
        if spf_header:
            t.auth.raw.append(" ".join(spf_header.split()))
            if not t.auth.spf:
                m = re.match(r"\s*([A-Za-z]+)", spf_header)
                if m:
                    t.auth.spf = m.group(1).lower()

    t.forefront = parse_forefront(msg)
    t.urls, t.body_addresses = extract_urls(msg)
    t.attachments = extract_attachments(msg)

    for extra in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        value = header(msg, extra)
        if value:
            t.notes.append("%s: %s" % (extra, value.strip("[]")))

    run_checks(t)
    return t


# ======================================================================
# Advanced Hunting CSV input
# ======================================================================

# Defender lets you rename columns in a project, and people do. Each indicator
# is looked up through a list of aliases rather than one exact header, so an
# export that says SenderAddress instead of SenderFromAddress still works.
CSV_COLUMNS = {
    "network_message_id": ["NetworkMessageId"],
    "internet_message_id": ["InternetMessageId"],
    "timestamp": ["Timestamp", "EmailTime", "TimeGenerated"],
    "subject": ["Subject"],
    "sender_from": ["SenderFromAddress", "SenderAddress", "SenderFrom"],
    "sender_mailfrom": ["SenderMailFromAddress", "SenderMailFrom", "ReturnPath"],
    "sender_from_domain": ["SenderFromDomain", "SenderDomain"],
    "sender_mailfrom_domain": ["SenderMailFromDomain"],
    "sender_ipv4": ["SenderIPv4", "SenderIP", "IPAddress"],
    "sender_ipv6": ["SenderIPv6"],
    "recipient": ["RecipientEmailAddress", "RecipientAddress", "AccountUpn", "Recipient"],
    "delivery_action": ["DeliveryAction", "EmailAction"],
    "delivery_location": ["DeliveryLocation", "EmailActionPolicy"],
    "threat_types": ["ThreatTypes", "EmailThreatTypes"],
    "detection_methods": ["DetectionMethods"],
    "auth_details": ["AuthenticationDetails"],
    "url": ["Url", "Urls"],
    "url_domain": ["UrlDomain"],
    "file_name": ["FileName", "AttachmentName"],
    "sha256": ["SHA256", "Sha256"],
}


def _csv_resolve(fieldnames: Sequence[str]) -> Dict[str, str]:
    lowered = {name.strip().lower(): name for name in fieldnames if name}
    resolved: Dict[str, str] = {}
    for key, aliases in CSV_COLUMNS.items():
        for alias in aliases:
            if alias.lower() in lowered:
                resolved[key] = lowered[alias.lower()]
                break
    return resolved


def _parse_auth_details(value: str) -> AuthResults:
    """EmailEvents.AuthenticationDetails, which is a JSON blob in a CSV cell.

    Shape varies between exports, so fall back to reading the mechanism names
    out of the raw text rather than insisting on valid JSON.
    """
    auth = AuthResults()
    if not value:
        return auth
    auth.raw = [value]
    parsed: Dict[str, Any] = {}
    try:
        loaded = json.loads(value)
        if isinstance(loaded, dict):
            parsed = loaded
        elif isinstance(loaded, list) and loaded and isinstance(loaded[0], dict):
            parsed = loaded[0]
    except (ValueError, TypeError):
        parsed = {}

    if parsed:
        lowered = {str(k).lower(): str(v).lower() for k, v in parsed.items() if v is not None}
        auth.spf = lowered.get("spf", "")
        auth.dkim = lowered.get("dkim", "")
        auth.dmarc = lowered.get("dmarc", "")
        auth.compauth = lowered.get("compauth", "")
    else:
        for mech, result in AUTH_MECH_RE.findall(value):
            mech = mech.lower()
            if not getattr(auth, mech, ""):
                setattr(auth, mech, result.lower())

    # "bestguesspass" is a Microsoft-specific DMARC value meaning no policy was
    # published and it inferred one. It is not a pass.
    if auth.dmarc.startswith("bestguess"):
        auth.dmarc_action = auth.dmarc
        auth.dmarc = "none"
    return auth


def load_hunting_csv(path: str) -> List[Triage]:
    """Turn an Advanced Hunting export into one Triage per message.

    EmailEvents emits one row per recipient, so rows are grouped by
    NetworkMessageId and the recipients collected — otherwise a message sent to
    forty people counts as forty messages and every total in the report is
    wrong.

    A CSV has no headers, no body and no attachment bytes, so the checks that
    read those are skipped rather than reported as clean. What survives is the
    part that matters most at campaign scale: sender alignment, authentication
    verdicts, delivery outcome, the recipient list, and the URLs — which are
    still Safe Links-unwrapped if the export carried them.
    """
    import csv

    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        try:
            dialect: Any = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = "excel"
        reader = csv.DictReader(fh, dialect=dialect)
        if not reader.fieldnames:
            raise SystemExit("%s has no header row — export from Advanced Hunting with column names." % path)

        columns = _csv_resolve(reader.fieldnames)
        if "sender_from" not in columns and "sender_mailfrom" not in columns:
            raise SystemExit(
                "%s has no sender column. Expected one of: %s.\n"
                "Export the results of an EmailEvents query, keeping the sender columns."
                % (path, ", ".join(CSV_COLUMNS["sender_from"] + CSV_COLUMNS["sender_mailfrom"]))
            )
        rows = list(reader)

    def cell(row: Dict[str, str], key: str) -> str:
        column = columns.get(key)
        if not column:
            return ""
        return (row.get(column) or "").strip()

    grouped: Dict[str, List[Dict[str, str]]] = {}
    order: List[str] = []
    for index, row in enumerate(rows):
        key = cell(row, "network_message_id") or "row-%d" % index
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(row)

    parsed_utc = utcnow()
    out: List[Triage] = []

    for key in order:
        group = grouped[key]
        first = group[0]

        t = Triage(source_file=os.path.basename(path), parsed_utc=parsed_utc, origin="csv")
        t.network_message_id = cell(first, "network_message_id")
        t.message_id = cell(first, "internet_message_id")
        t.date = cell(first, "timestamp")
        t.subject = cell(first, "subject")
        t.from_address = cell(first, "sender_from").lower()
        t.from_domain = cell(first, "sender_from_domain").lower() or domain_of_address(t.from_address)
        # SenderMailFromAddress is the envelope sender — the same identity the
        # Return-Path carries in a .eml, so the alignment check is identical.
        t.return_path = cell(first, "sender_mailfrom").lower()
        t.delivery_action = cell(first, "delivery_action")
        t.delivery_location = cell(first, "delivery_location")
        t.threat_types = cell(first, "threat_types")
        t.detection_methods = cell(first, "detection_methods")
        t.auth = _parse_auth_details(cell(first, "auth_details"))

        recipients: List[str] = []
        urls: List[ExtractedUrl] = []
        by_destination: Dict[str, ExtractedUrl] = {}
        hashes: List[Attachment] = []

        for row in group:
            recipient = cell(row, "recipient").lower()
            if recipient and recipient not in recipients:
                recipients.append(recipient)

            raw_url = cell(row, "url")
            if raw_url:
                cleaned = clean_url(raw_url)
                if cleaned.lower().startswith(("http://", "https://", "ftp://")):
                    destination, gateways = unwrap_url(cleaned)
                    if destination not in by_destination:
                        entry = ExtractedUrl(
                            url=destination,
                            original=cleaned,
                            domain=domain_of_url(destination),
                            sources=["EmailUrlInfo"],
                            rewriters=gateways,
                        )
                        by_destination[destination] = entry
                        urls.append(entry)

            sha256 = cell(row, "sha256").lower()
            if sha256 and not any(a.sha256 == sha256 for a in hashes):
                filename = cell(row, "file_name")
                extension = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
                hashes.append(
                    Attachment(
                        filename=filename or "(from export)",
                        content_type="(not in export)",
                        size=0,
                        sha256=sha256,
                        md5="",
                        extension=extension,
                        note=NOTABLE_EXTENSIONS.get(extension, ""),
                    )
                )

        t.to = recipients
        t.urls = urls
        t.attachments = hashes

        for ip_key in ("sender_ipv4", "sender_ipv6"):
            ip = cell(first, ip_key)
            if ip and is_public_ip(ip):
                t.hops.append(Hop(index=0, raw="(from export)", from_host="(from export)", ips=[ip]))

        run_checks(t)
        out.append(t)

    if not out:
        raise SystemExit("%s contained no data rows." % path)
    return out


# ======================================================================
# Enrichment — lookups only
# ======================================================================


class Throttle:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._last = 0.0

    def wait(self) -> None:
        if self.seconds <= 0:
            return
        delta = time.time() - self._last
        if self._last and delta < self.seconds:
            time.sleep(self.seconds - delta)
        self._last = time.time()


def _request(url: str, headers: Dict[str, str], data: Optional[bytes] = None) -> Tuple[int, Any]:
    """The only outbound HTTP in this tool.

    The allowlist check is the guard that makes "we never fetch a suspicious
    URL" a property of the code rather than a habit. If a future change tries
    to request an extracted URL, it raises here.
    """
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host not in NETWORK_ALLOWLIST:
        raise ValueError(
            "refusing to contact %r: not a reputation API. This tool never fetches URLs found in "
            "a message." % host
        )
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(body)
            except ValueError:
                return response.status, {"raw": body[:2000]}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, {"raw": body[:2000]}
    except (urllib.error.URLError, OSError) as exc:
        return 0, {"error": str(exc)}


def url_embeds_recipient(url: str) -> bool:
    """Does this URL carry an address or a base64 blob that probably is one?

    Credential-harvest links routinely pre-fill the victim's address in the
    query string or fragment. Sending that to a reputation service — or worse,
    submitting it to a public scanner — discloses who was targeted to a third
    party. Cheap to check, and the check decides what we are allowed to send.
    """
    if EMAIL_RE.search(urllib.parse.unquote(url)):
        return True
    tail = urllib.parse.urlsplit(url).query + urllib.parse.urlsplit(url).fragment
    # '=' only as trailing padding. Allowing it mid-token swallows the "d=" of a
    # query parameter into the candidate, and b64decode then fails on the whole
    # thing — which read as "no address embedded" and let it through.
    for token in re.findall(r"[A-Za-z0-9+/_\-]{16,}={0,2}", tail):
        padded = token.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            continue
        if EMAIL_RE.search(decoded):
            return True
    return False


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _vt_stats(payload: Any) -> Optional[Dict[str, Any]]:
    try:
        attributes = payload["data"]["attributes"]
    except (KeyError, TypeError):
        return None
    stats = attributes.get("last_analysis_stats") or {}
    out: Dict[str, Any] = {
        "malicious": stats.get("malicious"),
        "suspicious": stats.get("suspicious"),
        "harmless": stats.get("harmless"),
        "undetected": stats.get("undetected"),
    }
    if attributes.get("reputation") is not None:
        out["reputation"] = attributes["reputation"]
    for key in ("creation_date", "last_analysis_date", "first_submission_date"):
        if attributes.get(key):
            out[key] = datetime.datetime.fromtimestamp(
                attributes[key], datetime.timezone.utc
            ).strftime("%Y-%m-%d")
    for key in ("meaningful_name", "type_description", "title"):
        if attributes.get(key):
            out[key] = attributes[key]
    return out


def vt_lookup(kind: str, identifier: str, api_key: str, throttle: Throttle) -> Dict[str, Any]:
    """GET a VirusTotal report. Never POSTs. Never touches the file endpoints
    that accept an upload."""
    endpoint = {
        "url": "%s/urls/%s" % (VT_API, vt_url_id(identifier)),
        "file": "%s/files/%s" % (VT_API, identifier),
        "domain": "%s/domains/%s" % (VT_API, urllib.parse.quote(identifier, safe="")),
        "ip": "%s/ip_addresses/%s" % (VT_API, urllib.parse.quote(identifier, safe="")),
    }[kind]

    throttle.wait()
    status, payload = _request(endpoint, {"x-apikey": api_key, "Accept": "application/json"})

    if status == 404:
        return {"found": False, "note": "not in VirusTotal — never submitted by anyone, or new"}
    if status == 401:
        return {"error": "VirusTotal rejected the API key (401)"}
    if status == 429:
        return {"error": "VirusTotal quota exhausted (429) — free tier is 4/min, 500/day"}
    if status != 200:
        return {"error": "HTTP %s" % status, "detail": payload.get("error", payload) if isinstance(payload, dict) else None}

    stats = _vt_stats(payload)
    if stats is None:
        return {"error": "unexpected response shape"}
    stats["found"] = True
    stats["permalink"] = "https://www.virustotal.com/gui/%s/%s" % (
        {"url": "url", "file": "file", "domain": "domain", "ip": "ip-address"}[kind],
        vt_url_id(identifier) if kind == "url" else identifier,
    )
    return stats


def urlscan_search(query: str, api_key: str) -> Dict[str, Any]:
    """Search existing public scans. Does not scan anything."""
    endpoint = "%s/search/?q=%s&size=5" % (URLSCAN_API, urllib.parse.quote(query, safe=""))
    headers = {"Accept": "application/json"}
    if api_key:
        headers["API-Key"] = api_key
    status, payload = _request(endpoint, headers)
    if status == 429:
        return {"error": "urlscan rate limit (429)"}
    if status != 200 or not isinstance(payload, dict):
        return {"error": "HTTP %s" % status}
    results = payload.get("results") or []
    out: Dict[str, Any] = {"total": payload.get("total", len(results)), "results": []}
    for item in results[:5]:
        out["results"].append(
            {
                "url": (item.get("page") or {}).get("url"),
                "domain": (item.get("page") or {}).get("domain"),
                "scanned": (item.get("task") or {}).get("time"),
                "report": item.get("result"),
            }
        )
    return out


def submit_url_to_urlscan(url: str, api_key: str) -> Dict[str, Any]:
    """Submit a URL for scanning. Only reachable behind --submit.

    Note what is *not* in this file: there is no VirusTotal file-upload call and
    no code path that reads an attachment and sends it anywhere. Uploading an
    attachment pulled out of a user's mailbox ships whatever that mailbox
    contained to a third party, where on the free tier other customers can
    download it. Hash lookups answer the same question without that.

    Submissions here are forced to unlisted, and any URL carrying a recipient
    address is refused outright — a public scan of a personalised phishing link
    republishes who was targeted.
    """
    if not api_key:
        return {"error": "URLSCAN_API_KEY is not set; submission requires a key"}
    if url_embeds_recipient(url):
        return {"skipped": "URL embeds a recipient address — not submitted to a third party"}
    body = json.dumps({"url": url, "visibility": "unlisted"}).encode("utf-8")
    status, payload = _request(
        "%s/scan/" % URLSCAN_API,
        {"API-Key": api_key, "Content-Type": "application/json", "Accept": "application/json"},
        data=body,
    )
    if status not in (200, 201):
        return {"error": "HTTP %s" % status, "detail": payload if isinstance(payload, dict) else None}
    return {"submitted": True, "visibility": "unlisted", "report": payload.get("result"), "uuid": payload.get("uuid")}


def enrich(t: Triage, args: argparse.Namespace) -> None:
    vt_key = os.environ.get("VT_API_KEY", "").strip()
    urlscan_key = os.environ.get("URLSCAN_API_KEY", "").strip()

    if not vt_key:
        t.notes.append("--enrich: VT_API_KEY not set, VirusTotal lookups skipped.")
    if not urlscan_key:
        t.notes.append("--enrich: URLSCAN_API_KEY not set, urlscan searches run unauthenticated (lower limits).")

    throttle = Throttle(args.vt_rate)
    budget = args.max_lookups
    result: Dict[str, Any] = {"urls": {}, "domains": {}, "ips": {}, "files": {}, "submitted": {}}

    def spend() -> bool:
        nonlocal budget
        if budget <= 0:
            return False
        budget -= 1
        return True

    if vt_key:
        for url in [u.url for u in t.urls][: args.max_lookups]:
            if not spend():
                break
            if url_embeds_recipient(url):
                # Query the domain instead. The URL itself would carry the
                # victim's address into a third party's logs.
                domain = domain_of_url(url)
                result["urls"][url] = {
                    "skipped": "URL embeds a recipient address — queried the domain instead"
                }
                if domain and domain not in result["domains"]:
                    print("  VT domain %s" % domain, file=sys.stderr)
                    result["domains"][domain] = vt_lookup("domain", domain, vt_key, throttle)
                continue
            print("  VT url %s" % truncate(url, 70), file=sys.stderr)
            result["urls"][url] = vt_lookup("url", url, vt_key, throttle)

        for domain in t.url_domains + t.sender_domains:
            if domain in result["domains"] or not spend():
                continue
            print("  VT domain %s" % domain, file=sys.stderr)
            result["domains"][domain] = vt_lookup("domain", domain, vt_key, throttle)

        for ip in t.public_ips[:3]:
            if not spend():
                break
            print("  VT ip %s" % ip, file=sys.stderr)
            result["ips"][ip] = vt_lookup("ip", ip, vt_key, throttle)

        for att in t.attachments:
            if not spend():
                break
            print("  VT hash %s" % att.sha256[:16], file=sys.stderr)
            result["files"][att.sha256] = vt_lookup("file", att.sha256, vt_key, throttle)

    for domain in t.url_domains[:5]:
        print("  urlscan search domain:%s" % domain, file=sys.stderr)
        result["domains"].setdefault(domain, {})
        found = urlscan_search('domain:"%s"' % domain, urlscan_key)
        if isinstance(result["domains"][domain], dict):
            result["domains"][domain] = {"virustotal": result["domains"][domain], "urlscan": found}

    if args.submit:
        print(
            "\n--submit is set. Sending the following URLs to urlscan.io as UNLISTED scans:",
            file=sys.stderr,
        )
        for url in [u.url for u in t.urls]:
            print("    %s" % url, file=sys.stderr)
        for url in [u.url for u in t.urls]:
            result["submitted"][url] = submit_url_to_urlscan(url, urlscan_key)

    t.enrichment = result


# ======================================================================
# KQL generation
# ======================================================================


def kql_string(value: str) -> str:
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def kql_array(values: Sequence[str]) -> str:
    if not values:
        return "dynamic([])"
    if len(values) == 1:
        return "dynamic([%s])" % kql_string(values[0])
    inner = ",\n                             ".join(kql_string(v) for v in values)
    return "dynamic([%s])" % inner


def generate_kql(t: Triage, lookback: str = "14d") -> str:
    """Query for a single message."""
    return generate_kql_from_indicators(
        source_label=t.source_file,
        generated_utc=t.parsed_utc,
        sender_addresses=dedupe([t.from_address, t.return_path] + t.reply_to),
        sender_domains=t.sender_domains,
        # Deliberately excludes the gateway wrappers — see the header comment.
        urls=dedupe([u.url for u in t.urls]),
        url_domains=t.url_domains,
        hashes=dedupe([a.sha256 for a in t.attachments]),
        ips=t.public_ips,
        subjects=[t.subject] if t.subject else [],
        had_rewrites=any(u.was_rewritten for u in t.urls),
        lookback=lookback,
    )


def generate_kql_from_indicators(
    source_label: str,
    generated_utc: str,
    sender_addresses: Sequence[str],
    sender_domains: Sequence[str],
    urls: Sequence[str],
    url_domains: Sequence[str],
    hashes: Sequence[str],
    ips: Sequence[str],
    subjects: Sequence[str],
    had_rewrites: bool,
    lookback: str = "14d",
) -> str:
    """One query built from a set of indicators, whether they came from one
    message or from a whole campaign."""
    # EmailEvents splits SenderIPv4 and SenderIPv6. Only v4 goes in the array
    # below; a v6 sender needs the column swapped by hand.
    ips = [ip for ip in ips if ":" not in ip]

    lines: List[str] = []
    add = lines.append
    section = [0]

    def heading(text: str) -> str:
        """Number sections as they are emitted. A message with no
        attachments should not produce a query that jumps 3 -> 5."""
        section[0] += 1
        return "// %d. %s" % (section[0], text)

    add("// ============================================================================")
    add("// Defender XDR — Advanced Hunting")
    add("// Generated by triage.py %s from %s at %s" % (__version__, source_label, generated_utc))
    add("//")
    add("// Run each numbered section on its own. Widen `lookback` before you conclude")
    add("// the campaign is small — advanced hunting retains 30 days and nothing beyond")
    add("// that is absence of evidence. ago() is used throughout so there are no")
    add("// datetime() literals to get wrong; those are always UTC regardless of what")
    add("// the portal displays.")
    add("//")
    if had_rewrites:
        add("// Safe Links wrappers are deliberately NOT in phishUrls. The wrapper carries")
        add("// per-recipient data= and sdata= parameters, so matching on it finds only the")
        add("// one copy you already have. EmailUrlInfo and UrlClickEvents record the true")
        add("// destination, which is what is listed below.")
        add("//")
    add("// ============================================================================")
    add("")
    add("let lookback = %s;" % lookback)
    if sender_addresses:
        add("let senderAddresses  = %s;" % kql_array(sender_addresses))
    if sender_domains:
        add("let senderDomains    = %s;" % kql_array(sender_domains))
    if urls:
        add("let phishUrls        = %s;" % kql_array(urls))
    if url_domains:
        add("let phishUrlDomains  = %s;" % kql_array(url_domains))
    if hashes:
        add("let attachmentHashes = %s;" % kql_array(hashes))
    if ips:
        add("let senderIPs        = %s;" % kql_array(ips))
    if subjects:
        add("let subjectLines     = %s;" % kql_array(subjects))
    add("")

    # ---- 1 -----------------------------------------------------------
    add("// ----------------------------------------------------------------------------")
    add(heading("Every message from this sender, and where each one landed."))
    add("//    Start here: it answers 'who else got it' and 'is it still in a mailbox'.")
    add("// ----------------------------------------------------------------------------")
    add("EmailEvents")
    add("| where Timestamp > ago(lookback)")
    conditions = []
    if sender_addresses:
        conditions += ["SenderFromAddress in~ (senderAddresses)", "SenderMailFromAddress in~ (senderAddresses)"]
    if sender_domains:
        conditions += ["SenderFromDomain in~ (senderDomains)", "SenderMailFromDomain in~ (senderDomains)"]
    if conditions:
        add("| where " + ("\n     or ".join(conditions)))
    add("| project Timestamp, NetworkMessageId, InternetMessageId, Subject,")
    add("          SenderFromAddress, SenderMailFromAddress, SenderFromDomain, SenderIPv4,")
    add("          RecipientEmailAddress, DeliveryAction, DeliveryLocation,")
    add("          ThreatTypes, DetectionMethods, AuthenticationDetails")
    add("| order by Timestamp desc")
    add("")

    # ---- 2 -----------------------------------------------------------
    if urls or url_domains:
        add("// ----------------------------------------------------------------------------")
        add(heading("URL-first sweep. Run this even if the sender search looked contained."))
        add("//    Campaigns rotate the sending domain and keep the landing page, so a")
        add("//    sender-scoped search reports a campaign as one message.")
        add("// ----------------------------------------------------------------------------")
        add("let Hits =")
        add("EmailUrlInfo")
        url_conditions = []
        if urls:
            url_conditions.append("Url has_any (phishUrls)")
        if url_domains:
            url_conditions.append("UrlDomain in~ (phishUrlDomains)")
        add("| where " + ("\n     or ".join(url_conditions)))
        add("| project NetworkMessageId, Url, UrlDomain;")
        add("EmailEvents")
        add("| where Timestamp > ago(lookback)")
        add("| join kind=inner Hits on NetworkMessageId")
        add("| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain,")
        add("          RecipientEmailAddress, Subject, Url, UrlDomain,")
        add("          DeliveryAction, DeliveryLocation, ThreatTypes")
        add("| order by Timestamp desc")
        add("")

        # ---- 3 -------------------------------------------------------
        add("// ----------------------------------------------------------------------------")
        add(heading("Who clicked, and did they click through the warning page."))
        add("//    IsClickedThrough != 0 means the block was overridden. Those users are")
        add("//    the containment list; treat them as credential-entered until proven")
        add("//    otherwise, and go to the account-compromise playbook.")
        add("// ----------------------------------------------------------------------------")
        add("UrlClickEvents")
        add("| where Timestamp > ago(lookback)")
        # UrlClickEvents has no UrlDomain column; match the domain inside Url.
        click_conditions = []
        if urls:
            click_conditions.append("Url has_any (phishUrls)")
        if url_domains:
            click_conditions.append("Url has_any (phishUrlDomains)")
        add("| where " + ("\n     or ".join(click_conditions)))
        add("| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough,")
        add("          IPAddress, NetworkMessageId, ThreatTypes")
        add("| order by Timestamp desc")
        add("")

    # ---- 4 -----------------------------------------------------------
    if hashes:
        add("// ----------------------------------------------------------------------------")
        add(heading("The attachment, by hash — in mail and then on disk."))
        add("//    A hit in DeviceFileEvents means it left the mailbox and reached an")
        add("//    endpoint. That changes the incident from email triage to endpoint work.")
        add("// ----------------------------------------------------------------------------")
        add("EmailAttachmentInfo")
        add("| where Timestamp > ago(lookback)")
        add("| where SHA256 in~ (attachmentHashes)")
        add("| project Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress,")
        add("          FileName, FileType, SHA256, ThreatTypes")
        add("| order by Timestamp desc")
        add("")
        add("DeviceFileEvents")
        add("| where Timestamp > ago(lookback)")
        add("| where SHA256 in~ (attachmentHashes)")
        add("| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType,")
        add("          FileName, FolderPath, SHA256")
        add("| order by Timestamp desc")
        add("")

    # ---- 5 -----------------------------------------------------------
    if ips:
        add("// ----------------------------------------------------------------------------")
        add(heading("Everything else from the sending IP."))
        add("//    Baseline it before calling it hostile: an IP that shows up across weeks")
        add("//    is shared sending infrastructure, not attacker infrastructure.")
        add("// ----------------------------------------------------------------------------")
        add("EmailEvents")
        add("| where Timestamp > ago(30d)")
        add("| where SenderIPv4 in (senderIPs)")
        add("| summarize Messages = count(),")
        add("            Recipients = dcount(RecipientEmailAddress),")
        add("            Senders = make_set(SenderFromAddress, 20),")
        add("            Subjects = make_set(Subject, 20),")
        add("            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)")
        add("          by SenderIPv4, SenderFromDomain")
        add("| order by Messages desc")
        add("")

    # ---- 6 -----------------------------------------------------------
    if subjects:
        add("// ----------------------------------------------------------------------------")
        add(heading("Same lure, different sender. Subject-only, so expect noise —"))
        add("//    read the sender list, not the row count.")
        add("// ----------------------------------------------------------------------------")
        add("EmailEvents")
        add("| where Timestamp > ago(lookback)")
        add("| where Subject in~ (subjectLines)")
        add("| summarize Messages = count(), Recipients = dcount(RecipientEmailAddress),")
        add("            Senders = make_set(SenderFromAddress, 25)")
        add("          by Subject, SenderFromDomain")
        add("| order by Messages desc")
        add("")

    return "\n".join(lines)


# ======================================================================
# Campaign — many messages at once
# ======================================================================


@dataclass
class Campaign:
    """A set of messages triaged together.

    An incident is rarely one message. Triaging each in isolation gives you N
    reports and no answer to the only questions that matter at this scale: how
    many people received it, which copies were delivered, and what the union of
    indicators is. Everything here is derived across the whole set.
    """

    messages: List[Triage]
    parsed_utc: str
    source_label: str

    @property
    def recipients(self) -> List[str]:
        """The notification list. Reconcile this against whatever the
        notification team is working from — if yours is bigger, go back to them
        today."""
        return dedupe([r for m in self.messages for r in m.to])

    @property
    def senders(self) -> List[str]:
        return dedupe([m.from_address for m in self.messages if m.from_address])

    @property
    def sender_domains(self) -> List[str]:
        return dedupe([d for m in self.messages for d in m.sender_domains])

    @property
    def subjects(self) -> List[str]:
        return dedupe([m.subject for m in self.messages if m.subject])

    @property
    def urls(self) -> List[ExtractedUrl]:
        seen: Dict[str, ExtractedUrl] = {}
        for message in self.messages:
            for url in message.urls:
                if url.url not in seen:
                    seen[url.url] = url
        return list(seen.values())

    @property
    def url_domains(self) -> List[str]:
        return dedupe([d for m in self.messages for d in m.url_domains])

    @property
    def ips(self) -> List[str]:
        return dedupe([ip for m in self.messages for ip in m.public_ips])

    @property
    def attachments(self) -> List[Attachment]:
        seen: Dict[str, Attachment] = {}
        for message in self.messages:
            for att in message.attachments:
                seen.setdefault(att.sha256, att)
        return list(seen.values())

    @property
    def counts(self) -> Dict[str, int]:
        total = {"high": 0, "medium": 0, "info": 0}
        for message in self.messages:
            for severity, count in message.counts.items():
                total[severity] = total.get(severity, 0) + count
        return total

    def url_message_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for message in self.messages:
            for url in message.urls:
                counts[url.url] = counts.get(url.url, 0) + 1
        return counts

    def finding_rollup(self) -> List[Tuple[str, str, int]]:
        """(severity, title, message count), worst first. Collapses the same
        finding across messages so the report shows the shape of the campaign
        instead of the same paragraph forty times."""
        rollup: Dict[Tuple[str, str], int] = {}
        for message in self.messages:
            for finding in message.findings:
                rollup[(finding.severity, finding.title)] = rollup.get((finding.severity, finding.title), 0) + 1
        return sorted(
            [(sev, title, n) for (sev, title), n in rollup.items()],
            key=lambda row: (SEVERITY_ORDER.get(row[0], 9), -row[2]),
        )

    def delivery_breakdown(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for message in self.messages:
            if message.origin != "csv":
                continue
            key = message.delivery_action or "(not in export)"
            if message.delivery_location:
                key += " → " + message.delivery_location
            counts[key] = counts.get(key, 0) + 1
        return counts

    def date_range(self) -> Tuple[str, str]:
        stamps = sorted([m.date for m in self.messages if m.date])
        return (stamps[0], stamps[-1]) if stamps else ("", "")

    def to_ioc_dict(self) -> Dict[str, Any]:
        first, last = self.date_range()
        return {
            "tool": "triage.py",
            "version": __version__,
            "mode": "campaign",
            "source": self.source_label,
            "parsed_utc": self.parsed_utc,
            "shape": {
                "messages": len(self.messages),
                "distinct_senders": len(self.senders),
                "distinct_recipients": len(self.recipients),
                "distinct_subjects": len(self.subjects),
                "first_seen": first,
                "last_seen": last,
                "delivery": self.delivery_breakdown() or None,
            },
            "indicators": {
                "senders": self.senders,
                "sender_domains": self.sender_domains,
                "recipients": self.recipients,
                "subjects": self.subjects,
                "urls": [u.to_dict() for u in self.urls],
                "url_domains": self.url_domains,
                "originating_ips": self.ips,
                "attachment_sha256": [a.sha256 for a in self.attachments],
            },
            "findings": [
                {"severity": sev, "title": title, "messages": n} for sev, title, n in self.finding_rollup()
            ],
            "messages": [m.to_ioc_dict() for m in self.messages],
        }


def generate_campaign_kql(campaign: Campaign, lookback: str = "14d") -> str:
    return generate_kql_from_indicators(
        source_label=campaign.source_label,
        generated_utc=campaign.parsed_utc,
        sender_addresses=dedupe(
            [m.from_address for m in campaign.messages]
            + [m.return_path for m in campaign.messages]
            + [r for m in campaign.messages for r in m.reply_to]
        ),
        sender_domains=campaign.sender_domains,
        urls=dedupe([u.url for u in campaign.urls]),
        url_domains=campaign.url_domains,
        hashes=dedupe([a.sha256 for a in campaign.attachments]),
        ips=campaign.ips,
        subjects=campaign.subjects,
        had_rewrites=any(u.was_rewritten for u in campaign.urls),
        lookback=lookback,
    )


def render_campaign_markdown(campaign: Campaign, kql: str, do_defang: bool = True) -> str:
    def d(value: str) -> str:
        return defang(value) if do_defang else value

    out: List[str] = []
    add = out.append
    counts = campaign.counts
    first, last = campaign.date_range()

    add("# Phishing campaign triage — %s" % md_escape(campaign.source_label))
    add("")
    add("Parsed %s by `triage.py` %s." % (campaign.parsed_utc, __version__))
    add("")
    add(
        "**%d messages · %d recipients · %d senders.** Findings across the set: %d high, "
        "%d medium, %d informational. These are observations, not a verdict."
        % (
            len(campaign.messages),
            len(campaign.recipients),
            len(campaign.senders),
            counts["high"],
            counts["medium"],
            counts["info"],
        )
    )
    add("")

    # ---- shape ----
    add("## Campaign shape")
    add("")
    add("| | |")
    add("|---|---|")
    add("| Messages | %d |" % len(campaign.messages))
    add("| Distinct senders | %d |" % len(campaign.senders))
    add("| Distinct recipients | %d |" % len(campaign.recipients))
    add("| Distinct subjects | %d |" % len(campaign.subjects))
    add("| Distinct URLs | %d |" % len(campaign.urls))
    add("| Attachment hashes | %d |" % len(campaign.attachments))
    if first:
        add("| First seen | %s |" % md_escape(first))
        add("| Last seen | %s |" % md_escape(last))
    add("")

    delivery = campaign.delivery_breakdown()
    if delivery:
        add("### Delivery")
        add("")
        add("| Outcome | Messages |")
        add("|---|---|")
        for outcome, count in sorted(delivery.items(), key=lambda kv: -kv[1]):
            add("| %s | %d |" % (md_escape(outcome), count))
        add("")
        add("Anything delivered is still in a mailbox unless it has been purged. Confirm current "
            "state in Threat Explorer rather than assuming the export reflects it.")
        add("")

    # ---- findings rollup ----
    add("## Findings across the campaign")
    add("")
    rollup = campaign.finding_rollup()
    if not rollup:
        add("Nothing flagged. That is not a clean bill of health — see the README for the checks "
            "this tool does not perform.")
    else:
        add("| Severity | Finding | Messages |")
        add("|---|---|---|")
        for severity, title, count in rollup:
            add("| %s | %s | %d |" % (SEVERITY_LABEL.get(severity, "?"), md_escape(title), count))
        add("")
        add("Per-message detail and the reasoning behind each finding is in the individual "
            "sections below.")
    add("")

    # ---- senders ----
    add("## Senders")
    add("")
    add("| From | Envelope sender | SPF | DKIM | DMARC | Messages |")
    add("|---|---|---|---|---|---|")
    sender_rows: Dict[Tuple[str, str, str, str, str], int] = {}
    for message in campaign.messages:
        key = (
            message.from_address,
            message.return_path,
            message.auth.spf or "-",
            message.auth.dkim or "-",
            message.auth.dmarc or "-",
        )
        sender_rows[key] = sender_rows.get(key, 0) + 1
    for (sender, envelope, spf, dkim, dmarc), count in sorted(sender_rows.items(), key=lambda kv: -kv[1]):
        add(
            "| %s | %s | %s | %s | %s | %d |"
            % (
                md_escape(d(sender) or "-"),
                md_escape(d(envelope) or "-"),
                spf,
                dkim,
                dmarc,
                count,
            )
        )
    add("")

    # ---- subjects ----
    add("## Subjects")
    add("")
    subject_counts: Dict[str, int] = {}
    for message in campaign.messages:
        if message.subject:
            subject_counts[message.subject] = subject_counts.get(message.subject, 0) + 1
    if not subject_counts:
        add("None recorded.")
    else:
        add("| Subject | Messages |")
        add("|---|---|")
        for subject, count in sorted(subject_counts.items(), key=lambda kv: -kv[1]):
            add("| %s | %d |" % (md_escape(truncate(subject, 90)), count))
        add("")
        add("A campaign is usually one subject with a large count. Several subjects with one "
            "message each is either targeted or several campaigns in one bucket.")
    add("")

    # ---- recipients ----
    add("## Recipients")
    add("")
    add("%d distinct. **This is the notification list.** Reconcile it against whatever the "
        "notification team is working from — if yours is longer, go back to them today, and "
        "re-run scope after every new finding because this list only grows."
        % len(campaign.recipients))
    add("")
    for recipient in campaign.recipients:
        add("- `%s`" % d(recipient))
    add("")

    # ---- urls ----
    add("## URLs")
    add("")
    if not campaign.urls:
        add("None.")
    else:
        url_counts = campaign.url_message_counts()
        add("| Destination | Gateway-rewritten | Messages |")
        add("|---|---|---|")
        for url in sorted(campaign.urls, key=lambda u: -url_counts.get(u.url, 0)):
            add(
                "| `%s` | %s | %d |"
                % (
                    md_escape(d(truncate(url.url, 100))),
                    md_escape(", ".join(url.rewriters)) if url.was_rewritten else "no",
                    url_counts.get(url.url, 0),
                )
            )
        if any(u.was_rewritten for u in campaign.urls):
            add("")
            add("Destinations shown are after unwrapping. The gateway wrapper is what sits in the "
                "mailbox and is **not** what you block, search on, or look up.")
    add("")

    # ---- attachments ----
    add("## Attachments")
    add("")
    if not campaign.attachments:
        add("None.")
    else:
        add("| Filename | Type | SHA256 |")
        add("|---|---|---|")
        for att in campaign.attachments:
            add("| %s | %s | `%s` |" % (md_escape(att.filename), md_escape(att.content_type), att.sha256))
        add("")
        add("Hashes only. Nothing was uploaded anywhere.")
    add("")

    if campaign.ips:
        add("## Sending IPs")
        add("")
        for ip in campaign.ips:
            add("- `%s`" % d(ip))
        add("")
        add("Baseline before calling any of these hostile. An IP spanning weeks is shared sending "
            "infrastructure; one that appears cold and burns out in days is worth the escalation.")
        add("")

    # ---- per-message ----
    add("## Per-message detail")
    add("")
    for index, message in enumerate(campaign.messages, 1):
        label = message.subject or message.network_message_id or message.source_file
        add("<details>")
        add("<summary><b>%d. %s</b> — %s → %d recipient(s)</summary>" % (
            index,
            md_escape(truncate(label, 80)),
            md_escape(d(message.from_address) or "unknown sender"),
            len(message.to),
        ))
        add("")
        if message.network_message_id:
            add("NetworkMessageId: `%s`" % md_escape(message.network_message_id))
            add("")
        if message.origin == "csv" and message.delivery_action:
            add("Delivery: %s → %s" % (md_escape(message.delivery_action), md_escape(message.delivery_location or "-")))
            add("")
        if not message.findings:
            add("No findings.")
        for finding in message.findings:
            add("**%s — %s**" % (SEVERITY_LABEL.get(finding.severity, "?"), md_escape(finding.title)))
            add("")
            add(d(finding.detail))
            add("")
            add("*Why it matters:* %s" % finding.why)
            add("")
        add("</details>")
        add("")

    add("## Hunting query")
    add("")
    add("Built from the union of every indicator above. Run the sections one at a time.")
    add("")
    add("```kql")
    add(kql.rstrip())
    add("```")
    add("")

    return "\n".join(out)


# ======================================================================
# Rendering
# ======================================================================

SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "info": "INFO"}


def render_markdown(t: Triage, kql: str, do_defang: bool = True) -> str:
    def d(value: str) -> str:
        return defang(value) if do_defang else value

    out: List[str] = []
    add = out.append

    counts = t.counts
    add("# Phishing triage — %s" % md_escape(t.source_file))
    add("")
    add("Parsed %s by `triage.py` %s." % (t.parsed_utc, __version__))
    add("")
    add(
        "**%d high · %d medium · %d informational.** These are observations. This tool does not "
        "return a verdict — nothing below distinguishes a phish from a badly configured newsletter "
        "on its own." % (counts["high"], counts["medium"], counts["info"])
    )
    add("")
    if do_defang:
        add("URLs, domains and IPs are defanged below so a ticket does not linkify them. The JSON "
            "and the KQL carry the real values.")
        add("")

    # ---- message ----
    add("## Message")
    add("")
    add("| Field | Value |")
    add("|---|---|")
    add("| Subject | %s |" % md_escape(truncate(t.subject, 120) or "(none)"))
    add("| Date | %s |" % md_escape(t.date or "(none)"))
    add("| Message-ID | %s |" % md_escape(t.message_id or "(none)"))
    add("| From — display name | %s |" % md_escape(t.from_display or "(none)"))
    add("| From — address | %s |" % md_escape(d(t.from_address) or "(none)"))
    add("| Return-Path | %s |" % md_escape(d(t.return_path) or "(none)"))
    add("| Reply-To | %s |" % md_escape(", ".join(d(a) for a in t.reply_to) or "(none)"))
    add("| To | %s |" % md_escape(", ".join(d(a) for a in t.to) or "(none)"))
    if t.cc:
        add("| Cc | %s |" % md_escape(", ".join(d(a) for a in t.cc)))
    add("")

    # ---- authentication ----
    add("## Authentication")
    add("")
    if t.auth.raw:
        add("| Mechanism | Result |")
        add("|---|---|")
        add("| SPF | %s |" % md_escape(t.auth.spf or "not recorded"))
        add("| DKIM | %s |" % md_escape(t.auth.dkim or "not recorded"))
        add(
            "| DMARC | %s%s |"
            % (
                md_escape(t.auth.dmarc or "not recorded"),
                " (action=%s)" % md_escape(t.auth.dmarc_action) if t.auth.dmarc_action else "",
            )
        )
        add(
            "| compauth | %s%s |"
            % (
                md_escape(t.auth.compauth or "not recorded"),
                " (reason %s)" % md_escape(t.auth.compauth_reason) if t.auth.compauth_reason else "",
            )
        )
        if t.auth.smtp_mailfrom:
            add("| smtp.mailfrom | %s |" % md_escape(d(t.auth.smtp_mailfrom)))
        if t.auth.header_from:
            add("| header.from | %s |" % md_escape(d(t.auth.header_from)))
    else:
        add("No `Authentication-Results` header in this file.")
    if t.forefront:
        add("")
        add("EOP verdict: " + ", ".join("`%s:%s`" % (k, v) for k, v in sorted(t.forefront.items())) + ".")
    add("")

    # ---- findings ----
    add("## Findings")
    add("")
    if not t.findings:
        add("Nothing flagged. That is not a clean bill of health — see the checks this tool does "
            "not perform, in the README.")
    for finding in t.findings:
        add("### %s — %s" % (SEVERITY_LABEL.get(finding.severity, "?"), md_escape(finding.title)))
        add("")
        add(d(finding.detail))
        add("")
        add("*Why it matters:* %s" % finding.why)
        add("")

    # ---- urls ----
    add("## URLs")
    add("")
    if not t.urls:
        add("No URLs in the body parts.")
    else:
        add("| # | Destination | Gateway-rewritten | Source |")
        add("|---|---|---|---|")
        for index, url in enumerate(t.urls, 1):
            add(
                "| %d | `%s` | %s | %s |"
                % (
                    index,
                    md_escape(d(truncate(url.url, 100))),
                    md_escape(", ".join(url.rewriters)) if url.was_rewritten else "no",
                    md_escape(", ".join(url.sources)),
                )
            )
        rewritten = [u for u in t.urls if u.was_rewritten]
        if rewritten:
            add("")
            add("Wrapped originals, for reference — these are what sits in the mailbox, and they are "
                "**not** what you block or search on:")
            add("")
            for url in rewritten:
                add("- `%s`" % md_escape(d(truncate(url.original, 160))))
    if t.body_addresses:
        add("")
        add("Addresses referenced in the body: %s" % ", ".join("`%s`" % d(a) for a in t.body_addresses))
    add("")

    # ---- attachments ----
    add("## Attachments")
    add("")
    if not t.attachments:
        add("None.")
    else:
        add("| Filename | Type | Bytes | SHA256 |")
        add("|---|---|---|---|")
        for att in t.attachments:
            add(
                "| %s | %s | %d | `%s` |"
                % (md_escape(att.filename), md_escape(att.content_type), att.size, att.sha256)
            )
        add("")
        add("Hashes only. Nothing here was uploaded anywhere, and this tool has no code path that "
            "would upload one.")
    add("")

    # ---- received ----
    add("## Received chain")
    add("")
    if not t.hops:
        add("No `Received` headers.")
    else:
        add("Newest hop first, as the headers appear. The oldest hop is the bottom row.")
        add("")
        add("| Hop | From | By | IPs | Timestamp |")
        add("|---|---|---|---|---|")
        for hop in t.hops:
            add(
                "| %d | %s | %s | %s | %s |"
                % (
                    hop.index,
                    md_escape(d(truncate(hop.from_host, 45)) or "-"),
                    md_escape(d(truncate(hop.by_host, 45)) or "-"),
                    md_escape(", ".join(d(ip) for ip in hop.ips) or "-"),
                    md_escape(truncate(hop.timestamp, 40) or "-"),
                )
            )
    if t.notes:
        add("")
        for note in t.notes:
            add("- %s" % md_escape(note))
    add("")

    # ---- enrichment ----
    if t.enrichment:
        add("## Enrichment")
        add("")
        add("Reputation lookups only. No URL in this message was fetched from this workstation.")
        add("")
        add("```json")
        add(json.dumps(t.enrichment, indent=2, sort_keys=True))
        add("```")
        add("")

    # ---- kql ----
    add("## Hunting query")
    add("")
    add("Paste into Defender XDR > Hunting > Advanced hunting. Run the sections one at a time.")
    add("")
    add("```kql")
    add(kql.rstrip())
    add("```")
    add("")

    return "\n".join(out)


# ======================================================================
# CLI
# ======================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage.py",
        description="Triage a saved phishing email: headers, spoofing checks, IOCs, and a "
        "ready-to-run Defender Advanced Hunting query.",
        epilog="Never fetches an extracted URL. Never uploads an attachment. Submits nothing "
        "unless --submit is given.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="one or more .eml files, a directory of them, or the password-protected .zip that "
        "Defender's Download email action produces. More than one message switches to campaign "
        "mode: one combined report and one query covering the whole set.",
    )
    parser.add_argument(
        "--zip-password",
        metavar="PW",
        help="password for a Defender download ZIP. Omit it and you are prompted, which keeps it "
        "out of your shell history.",
    )
    parser.add_argument(
        "--csv",
        metavar="PATH",
        help="an Advanced Hunting CSV export (EmailEvents, optionally joined with EmailUrlInfo "
        "or EmailAttachmentInfo) instead of .eml files. Rows are grouped by NetworkMessageId.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "kql"),
        default="markdown",
        help="what to write to stdout (default: markdown)",
    )
    parser.add_argument("--json", metavar="PATH", help="write raw IOCs as JSON to PATH")
    parser.add_argument("--md", metavar="PATH", help="write the markdown summary to PATH")
    parser.add_argument("--kql", metavar="PATH", help="write the hunting query to PATH")
    parser.add_argument(
        "--outdir",
        metavar="DIR",
        help="write all three (-triage.md, -iocs.json, -hunt.kql) into DIR",
    )
    parser.add_argument(
        "--lookback", default="14d", help="lookback for the generated KQL (default: 14d)"
    )
    parser.add_argument(
        "--no-defang",
        action="store_true",
        help="leave URLs clickable in the markdown output (JSON and KQL are never defanged)",
    )
    parser.add_argument(
        "--no-unwrap-forwarded",
        action="store_true",
        help="triage the wrapper rather than the message/rfc822 attachment inside it",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="look up indicators in VirusTotal and urlscan.io (VT_API_KEY, URLSCAN_API_KEY)",
    )
    parser.add_argument(
        "--max-lookups",
        type=int,
        default=8,
        help="cap on VirusTotal lookups per run (default: 8; free tier is 500/day)",
    )
    parser.add_argument(
        "--vt-rate",
        type=float,
        default=VT_DEFAULT_RATE_SECONDS,
        help="seconds between VirusTotal requests (default: %.0f, the free-tier limit)"
        % VT_DEFAULT_RATE_SECONDS,
    )
    parser.add_argument(
        "--submit",
        action="store_true",
        help="OFF BY DEFAULT. Submit extracted URLs to urlscan.io as unlisted scans. "
        "Attachments are never submitted anywhere, with or without this flag.",
    )
    parser.add_argument("--version", action="version", version="triage.py " + __version__)
    return parser


def expand_inputs(paths: Sequence[str], zip_password: Optional[str]) -> List[Tuple[str, bytes]]:
    """Resolve arguments to (label, raw message bytes).

    Accepts .eml files, directories of them, and Defender's password-protected
    ZIP download. Directory listings are sorted so `--outdir` output is
    reproducible.
    """
    resolved: List[Tuple[str, bytes]] = []
    for path in paths:
        if os.path.isdir(path):
            found = sorted(
                os.path.join(path, name)
                for name in os.listdir(path)
                if name.lower().endswith((".eml", ".zip"))
            )
            if not found:
                raise SystemExit("no .eml or .zip files in %s" % path)
            resolved.extend(expand_inputs(found, zip_password))
        elif os.path.isfile(path):
            if path.lower().endswith(".zip"):
                resolved.extend(load_zip_messages(path, zip_password))
            else:
                with open(path, "rb") as fh:
                    resolved.append((path, fh.read()))
        else:
            raise SystemExit("no such file or directory: %s" % path)
    return resolved


def triage_one_file(label: str, raw: bytes, unwrap_forwarded: bool) -> Triage:
    msg = parse_message_bytes(raw, os.path.basename(label))
    pre_notes: List[str] = []
    if unwrap_forwarded:
        embedded = find_embedded_message(msg)
        if embedded is not None:
            pre_notes.append(
                "This file contained a message/rfc822 attachment and that attached message was "
                "triaged instead of the wrapper — a reported phish carries the reporting user's "
                "headers, not the sender's. Re-run with --no-unwrap-forwarded to see the wrapper."
            )
            msg = embedded
    t = triage_message(msg, label)
    t.notes = pre_notes + t.notes
    return t


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.paths and not args.csv:
        print("give one or more .eml files, a directory, or --csv EXPORT.csv", file=sys.stderr)
        return 2
    if args.paths and args.csv:
        print("--csv and .eml inputs are separate modes; pass one or the other.", file=sys.stderr)
        return 2
    if args.submit and not args.enrich:
        print("--submit does nothing without --enrich.", file=sys.stderr)
        return 2

    # ---- gather ------------------------------------------------------
    if args.csv:
        if not os.path.isfile(args.csv):
            print("no such file: %s" % args.csv, file=sys.stderr)
            return 2
        messages = load_hunting_csv(args.csv)
        source_label = os.path.basename(args.csv)
        campaign_mode = True
        stem = os.path.splitext(os.path.basename(args.csv))[0]
    else:
        zip_password = args.zip_password
        if zip_password is None and any(p.lower().endswith(".zip") for p in args.paths):
            # Prompt rather than take it on the command line, so the password
            # for an evidence archive does not sit in shell history.
            import getpass

            zip_password = getpass.getpass("ZIP password (blank if none): ") or None

        files = expand_inputs(args.paths, zip_password)
        messages = [
            triage_one_file(label, raw, not args.no_unwrap_forwarded) for label, raw in files
        ]
        campaign_mode = len(messages) > 1
        source_label = (
            os.path.basename(files[0][0])
            if len(files) == 1
            else "%d messages" % len(files)
        )
        stem = (
            os.path.splitext(os.path.basename(files[0][0]))[0] if len(files) == 1 else "campaign"
        )

    # ---- analyse -----------------------------------------------------
    if campaign_mode:
        campaign = Campaign(messages=messages, parsed_utc=utcnow(), source_label=source_label)
        if args.enrich:
            print(
                "Enriching campaign indicators (lookups only, no submissions unless --submit)...",
                file=sys.stderr,
            )
            # Enrich once across the union rather than per message — otherwise a
            # forty-message campaign spends its whole VirusTotal quota on forty
            # lookups of the same URL.
            merged = Triage(source_file=source_label, parsed_utc=campaign.parsed_utc)
            merged.urls = campaign.urls
            merged.attachments = campaign.attachments
            merged.from_domain = campaign.sender_domains[0] if campaign.sender_domains else ""
            merged.hops = [Hop(index=0, raw="", ips=campaign.ips)]
            try:
                enrich(merged, args)
            except ValueError as exc:
                print("enrichment aborted: %s" % exc, file=sys.stderr)
                return 1
            campaign_enrichment = merged.enrichment
        else:
            campaign_enrichment = {}

        kql = generate_campaign_kql(campaign, args.lookback)
        markdown = render_campaign_markdown(campaign, kql, do_defang=not args.no_defang)
        ioc_dict = campaign.to_ioc_dict()
        if campaign_enrichment:
            ioc_dict["enrichment"] = campaign_enrichment
        iocs = json.dumps(ioc_dict, indent=2, sort_keys=False)
    else:
        t = messages[0]
        if args.enrich:
            print("Enriching (lookups only, no submissions unless --submit)...", file=sys.stderr)
            try:
                enrich(t, args)
            except ValueError as exc:
                print("enrichment aborted: %s" % exc, file=sys.stderr)
                return 1
        kql = generate_kql(t, args.lookback)
        markdown = render_markdown(t, kql, do_defang=not args.no_defang)
        iocs = json.dumps(t.to_ioc_dict(), indent=2, sort_keys=False)

    # ---- write -------------------------------------------------------
    written: List[str] = []

    def write(path: str, content: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content if content.endswith("\n") else content + "\n")
        written.append(path)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        write(os.path.join(args.outdir, stem + "-triage.md"), markdown)
        write(os.path.join(args.outdir, stem + "-iocs.json"), iocs)
        write(os.path.join(args.outdir, stem + "-hunt.kql"), kql)
    if args.md:
        write(args.md, markdown)
    if args.json:
        write(args.json, iocs)
    if args.kql:
        write(args.kql, kql)

    if written:
        for path in written:
            print("wrote %s" % path, file=sys.stderr)
    else:
        sys.stdout.write({"markdown": markdown, "json": iocs, "kql": kql}[args.format] + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
