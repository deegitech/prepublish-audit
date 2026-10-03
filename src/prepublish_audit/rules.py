"""Built-in rules: secret patterns, leak heuristics and the rule catalogue.

Content rules run a regular expression over text and then a validator that
throws away placeholders and known-benign shapes. File rules look at a path
only. The remaining catalogue entries (metadata, git, config and scan rules)
are produced by other modules; they are listed here so that every report and
the SARIF rule table describe them the same way.
"""

from __future__ import annotations

import base64
import binascii
import bisect
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Callable, Dict, FrozenSet, List, Optional, Pattern, Tuple, Union

from . import doc_url
from .config import Settings
from .util import (
    LineIndex,
    WELL_KNOWN_NUMBERS,
    is_placeholder,
    is_placeholder_number,
    is_round_number,
    looks_sequential,
    luhn_ok,
    shannon_entropy,
)

# Content targets: where a rule runs.
TEXT = "text"          # text files, archive members, document text
PATH = "path"          # file and archive member names
BINARY = "binary"      # printable strings pulled out of binary files
META = "metadata"      # metadata values (EXIF, XMP, PDF info, ffprobe tags...)
COMMIT = "commit"      # commit and tag messages
REF = "ref"            # branch and tag names
DECODED = "decoded"    # base64 / percent / entity-decoded views of text

ALL = frozenset({TEXT, PATH, BINARY, META, COMMIT, REF, DECODED})
SECRETS = frozenset({TEXT, BINARY, META, COMMIT, DECODED})
PROSE = frozenset({TEXT, META, COMMIT})

# PEM blocks whose content is public by design. "[A-Z0-9 ]{0,40}" and the
# lazy body stop at the first END line, so the pattern stays linear.
_PUBLIC_PEM = re.compile(
    r"-----BEGIN (?:TRUSTED )?(?:CERTIFICATE(?: REQUEST)?|X509 CRL|PKCS7|PUBLIC KEY|RSA PUBLIC KEY|"
    r"NEW CERTIFICATE REQUEST)-----[A-Za-z0-9+/=\s]{0,1048576}?-----END [A-Z0-9 ]{0,40}-----"
)


class RuleContext:
    """What a validator may look at around one match.

    One context is created per scanned text and re-bound for every match, so
    validators get O(1) access to the surrounding line even in multi-megabyte
    minified files.
    """

    __slots__ = ("text", "index", "settings", "path", "target", "start", "end", "_lo", "_hi", "_pem")

    def __init__(self, text: str, index: LineIndex, settings: Settings, path: Optional[str], target: str) -> None:
        self.text = text
        self.index = index
        self.settings = settings
        self.path = path
        self.target = target
        self.start = self.end = 0
        self._lo = self._hi = 0
        self._pem: Optional[List[Tuple[int, int]]] = None

    def in_public_pem_block(self) -> bool:
        """True inside a PEM block of public material (certificate, public key, CSR, CRL).

        CA bundles hold thousands of base64 lines that are meant to be
        published. The block spans are found once per text.
        """
        if self._pem is None:
            self._pem = [(m.start(), m.end()) for m in _PUBLIC_PEM.finditer(self.text)] \
                if "-----BEGIN " in self.text else []
        if not self._pem:
            return False
        i = bisect.bisect_right(self._pem, (self.start, len(self.text) + 1)) - 1
        return i >= 0 and self._pem[i][0] <= self.start < self._pem[i][1]

    def bind(self, start: int, end: int) -> "RuleContext":
        self.start, self.end = start, end
        line, _ = self.index.position(start)
        self._lo, _ = self.index.line_bounds(line)
        end_line, _ = self.index.position(max(start, end - 1))
        _, self._hi = self.index.line_bounds(end_line)
        return self

    @property
    def line_length(self) -> int:
        return self._hi - self._lo

    @property
    def line(self) -> str:
        """The line around the match (a window of it when the line is huge)."""
        lo = max(self._lo, self.start - 1000)
        hi = min(self._hi, self.end + 1000)
        return self.text[lo:hi]

    def before(self, n: int) -> str:
        return self.text[max(self._lo, self.start - n): self.start]

    def after(self, n: int) -> str:
        return self.text[self.end: min(self._hi, self.end + n)]


Verdict = Union[bool, str, None]
Validator = Callable[[str, "re.Match[str]", RuleContext], Verdict]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    remediation: str
    pattern: Optional[Pattern[str]] = None
    group: Union[int, str] = 0
    """Group holding the sensitive value; -1 means the first group that matched."""
    keywords: Tuple[str, ...] = ()
    targets: FrozenSet[str] = frozenset({TEXT})
    validate: Optional[Validator] = None
    priority: int = 100
    kind: str = "content"
    tags: Tuple[str, ...] = ()

    @property
    def category(self) -> str:
        return self.id.split(".", 1)[0]


# ---------------------------------------------------------------------------
# Shared validator helpers

def _not_placeholder(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    return not is_placeholder(value)


def _entropy_at_least(threshold: float) -> Validator:
    def check(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
        return shannon_entropy(value) >= threshold and not is_placeholder(value)
    return check


def _in_url(ctx: RuleContext) -> bool:
    before = ctx.before(300)
    token = re.split(r"[\s\"'`<>()\[\]{}]", before)[-1]
    return "://" in token and not token.lower().startswith("file:")


# ---------------------------------------------------------------------------
# Secret validators

_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{40,}")


def _v_private_key(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    tail = ctx.text[m.end(): m.end() + 2500]
    if value.startswith("PuTTY"):
        return "Private-Lines:" in tail
    return _B64_RUN.search(tail[:700]) is not None


def _v_aws_key_id(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    return "EXAMPLE" not in value and len(set(value[4:])) > 4


def _v_jwt(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    parts = value.split(".")
    try:
        header = json.loads(_b64url(parts[0]))
        payload = _b64url(parts[1]).decode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return False
    if not isinstance(header, dict) or "alg" not in header:
        return False
    lowered = payload.lower()
    if "john doe" in lowered or "1234567890" in payload:
        return False  # the jwt.io sample token
    return True


def _b64url(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


_URL_PASSWORD_PLACEHOLDERS = {
    "password", "passwd", "pass", "pwd", "secret", "pw", "x-oauth-basic", "token", "changeme",
    "user", "username", "test", "admin", "root", "postgres", "mysql", "guest", "anonymous",
}


def _v_url_password(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if value.lower() in _URL_PASSWORD_PLACEHOLDERS or value[:1] in "$%{<[*" or is_placeholder(value):
        return False
    return len(value) >= 3


def _v_basic_auth(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    scheme = m.group("scheme").lower()
    if scheme == "basic":
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=False).decode("utf-8", "strict")
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return False
        if ":" not in decoded:
            return False
        password = decoded.split(":", 1)[1]
        return bool(password) and password.lower() not in _URL_PASSWORD_PLACEHOLDERS and not is_placeholder(password)
    return shannon_entropy(value) >= 3.5 and any(c.isdigit() for c in value) and not is_placeholder(value)


_ASSIGN_IGNORED_VALUE = re.compile(
    r"^(?:[a-z]+(?:[_.-][a-z]+)*|[A-Z][A-Z0-9_]+|https?://.*|/.*|\..*|.*\.(?:json|ya?ml|txt|pem|key|env|toml|ini))$"
)


_TEST_MARKER = re.compile(r"(?:^|[^a-z])(?:test|fake|mock|stub|do-not-leak|dont-leak)(?:[^a-z]|$)", re.IGNORECASE)


def _v_generic_assignment(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if is_placeholder(value) or _ASSIGN_IGNORED_VALUE.match(value) or _TEST_MARKER.search(value):
        return False
    lowered = value.lower()
    if any(word in lowered for word in ("process.env", "os.environ", "getenv", "secrets.", "vault:", "ssm:", "arn:")):
        return False
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    if shannon_entropy(value) >= 3.0 and has_digit and has_alpha:
        return True
    return len(value) >= 16 and shannon_entropy(value) >= 3.5


_ENTROPY_SKIP_FILES = re.compile(
    r"(?:^|/)(?:[^/]*\.lock|[^/]*-lock\.(?:json|ya?ml)|go\.sum|[^/]*\.min\.(?:js|css)|[^/]*\.map|"
    r"[^/]*\.svg|[^/]*\.pdf|[^/]*\.ipynb|npm-shrinkwrap\.json)$",
    re.IGNORECASE,
)
_ENTROPY_SKIP_LINE = re.compile(
    r"integrity|sha(?:1|224|256|384|512)-|checksum|\bhash\b|digest|data:[a-z]+/[a-z0-9.+-]+;base64|"
    r"sourceMappingURL|nonce|\bsalt\b|\buuid\b|\bguid\b",
    re.IGNORECASE,
)


def _v_entropy(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    s = ctx.settings
    token = value.rstrip("=")
    if len(token) < s.entropy_min_length or ctx.line_length > 1000:
        return False
    if ctx.path and _ENTROPY_SKIP_FILES.search(ctx.path):
        return False
    if not (any(c.isdigit() for c in token) and any(c.islower() for c in token) and any(c.isupper() for c in token)):
        return False
    if re.fullmatch(r"[0-9a-fA-F]+", token):
        return False
    if _ENTROPY_SKIP_LINE.search(ctx.line):
        return False
    if ctx.in_public_pem_block():
        return False  # certificate and public-key bodies are meant to be published
    # path-like tokens: several plain words separated by slashes
    if "/" in token and sum(1 for part in token.split("/") if re.fullmatch(r"[A-Za-z][a-z]{2,}", part)) >= 2:
        return False
    if is_placeholder(token):
        return False
    # Identifiers and file names (CamelCase, snake_case, WORD-WORD_1080x1920)
    # are built from long runs of one character class; random tokens switch
    # class every one or two characters.
    runs = [len(m.group()) for m in _CLASS_RUN.finditer(token)]
    if runs and (len(token) / len(runs) > 2.5 or max(runs) > 7):
        return False
    return shannon_entropy(token) >= s.entropy_threshold


_CLASS_RUN = re.compile(r"[A-Z]+|[a-z]+|[0-9]+|[^A-Za-z0-9]+")


# ---------------------------------------------------------------------------
# Leak validators

def _v_home_path(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    name = (m.group("uname") or m.group("wname") or "").strip()
    if not name or name[0] in "$<{%~*.(" or name.isupper():
        return False
    allowed = {u.lower() for u in ctx.settings.allowed_home_users}
    if name.lower() in allowed:
        return False
    if m.group("uname") is not None:
        base = m.group("base")
        if base == "home" and not (m.group("rest") or "").strip("/"):
            return False
        if _in_url(ctx):
            return False
    return True


_VOLUME_PLACEHOLDERS = {"macintosh", "untitled", "volumename", "volume", "name", "drive", "disk", "usb"}


def _v_volume(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    name = m.group(1)
    if not name or name[0] in "$<{%*" or name.lower() in _VOLUME_PLACEHOLDERS or name.isupper():
        return False
    return not _in_url(ctx)


_PLACEHOLDER_LOCALPARTS = {
    "user", "username", "name", "email", "someone", "you", "yourname", "your.name", "your_name",
    "your-name", "your_email", "your-email", "youremail", "john.doe", "jane.doe", "johndoe",
    "janedoe", "foo", "bar", "first.last", "firstname.lastname",
}


def _domain_allowed(domain: str, allowed: List[str]) -> bool:
    d = domain.lower().rstrip(".")
    for a in allowed:
        a = a.lower().lstrip("*").lstrip(".")
        if d == a or d.endswith("." + a):
            return True
    return False


_LOCKFILE = re.compile(
    r"(?:^|/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|"
    r"Pipfile\.lock|uv\.lock|pdm\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock|Podfile\.lock|"
    r"Package\.resolved|packages\.lock\.json|gradle\.lockfile|flake\.lock|mix\.lock|pubspec\.lock)$"
)


def in_lockfile(ctx: RuleContext) -> bool:
    """Lockfiles are full of third-party emails, hashes and versions."""
    return bool(ctx.path) and _LOCKFILE.search(ctx.path) is not None  # type: ignore[arg-type]


def _v_email(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if in_lockfile(ctx):
        return False
    local, _, domain = value.rpartition("@")
    s = ctx.settings
    if value.lower() in {e.lower() for e in s.allowed_emails}:
        return False
    if _domain_allowed(domain, s.allowed_email_domains):
        return False
    first_label = domain.split(".", 1)[0]
    if re.fullmatch(r"\d+(?:\.\d+)?x", first_label):  # icon@2x.png
        return False
    if local.lower() in _PLACEHOLDER_LOCALPARTS or local[:1] in "{<$%":
        return False
    if re.fullmatch(r"(?:no-?reply|do-?not-?reply|bounces?|mailer-daemon)(?:[+._-].*)?", local.lower()):
        return False  # role addresses that exist to be published (bots, notifications)
    return True


_TIME_CONTEXT = re.compile(
    r"(?:time|date|stamp|expir|epoch|created|updated|modified|since|until|_at\b|At\b|\bexp\b|\biat\b|\bnbf\b|\bts\b|\bmtime\b)"
    r"[\"'\]]?\s*[:=(,]?\s*[\"'(\[]?\s*$",
    re.IGNORECASE,
)
_HASH_CONTEXT = re.compile(r"sha\d*|md5|crc|checksum|hash|digest|integrity|isbn|issn|doi\b|\bversion\b|\bserial\b",
                           re.IGNORECASE)
_UUID_HEAD = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-$")


def _v_numeric_id(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if in_lockfile(ctx):
        return False
    s = value
    if s in WELL_KNOWN_NUMBERS or s in _TEST_CARDS or is_round_number(s) or is_placeholder_number(s):
        return False
    if s in ctx.settings.allowed_numbers:
        return False
    text, start, end = ctx.text, ctx.start, ctx.end
    if start >= 2 and text[start - 1] in ".," and text[start - 2].isdigit():
        return False  # decimal fraction such as 3.14159265358979
    if start >= 1 and text[start - 1] in "eE" and start >= 2 and text[start - 2] in "+-.0123456789":
        return False
    # Expand to the surrounding alphanumeric token.
    lo = start
    while lo > 0 and text[lo - 1].isalnum():
        lo -= 1
        if start - lo > 64:
            return False  # part of a long token: a hash, blob or base64 run
    hi = end
    while hi < len(text) and text[hi].isalnum():
        hi += 1
        if hi - end > 64:
            return False
    prefix, suffix = text[lo:start], text[end:hi]
    if prefix.lower().startswith("0x") or len(prefix) > 4 or len(suffix) > 4:
        return False
    if prefix and suffix and re.fullmatch(r"[0-9a-fA-F]*", prefix + suffix):
        return False
    if _UUID_HEAD.search(text[max(0, start - 24): start]):
        return False
    before = ctx.before(60)
    if _TIME_CONTEXT.search(before) or _HASH_CONTEXT.search(before):
        return False
    return True


_DOC_NETWORKS = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
)]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _v_ip(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if in_lockfile(ctx):
        return False
    if ":" in value and (value.count(":") < 2 or "::" not in value and value.count(":") != 7):
        return False
    if "." in value and any(len(part) > 1 and part.startswith("0") for part in value.split(".")):
        return False  # 01.02.03.04 is a version or date, not an address
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if value in ctx.settings.allowed_ips:
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return False
    if any(ip in net for net in _DOC_NETWORKS):
        return False
    after = ctx.after(4)
    if after.startswith("/") and after[1:2].isdigit():
        return False  # a CIDR range, not a host
    if re.search(r"(?:version|ver\.?|v)\s*$", ctx.before(12), re.IGNORECASE):
        return False
    if ip.version == 4:
        if ip in _CGNAT:
            return "shared address space, often a VPN or tailnet"
        if ip.is_private:
            return "private network"
        if ip.is_reserved or ip.is_link_local:
            return False
        return "public address"
    groups = [g for g in value.split(":") if g]
    if len(groups) < 3 or ip.is_reserved:
        return False  # slices such as a[1::2], or reserved space
    if ip.is_link_local:
        return "IPv6 link-local" if "ff:fe" in value.lower() else False
    if ip.is_private:
        return "IPv6 unique local"
    if ip.is_global:
        return "public IPv6 address"
    return False


_CODE_RECEIVERS = {
    "this", "self", "cls", "window", "document", "process", "module", "exports", "config", "settings",
    "options", "opts", "props", "state", "ctx", "context", "app", "args", "kwargs", "os", "sys", "env",
    "obj", "data", "item", "result", "res", "req", "request", "response", "super", "store", "model",
    "params", "vm", "scope", "record", "row", "node", "el", "event", "e", "err", "x", "y", "it",
}


def _v_internal_host(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    host = value.lower()
    if host in {h.lower() for h in ctx.settings.allowed_hosts} or is_placeholder(host):
        return False
    labels = host.split(".")
    if labels[0] in _CODE_RECEIVERS:
        return False
    before = ctx.before(3)
    if before.endswith(("://", "@", "\\\\")):
        return True
    if "-" in labels[0] or any(c.isdigit() for c in labels[0]):
        return True
    suffix_len = 2 if host.endswith(".home.arpa") else 1
    return len(labels) - suffix_len >= 2


_UNC_PLACEHOLDERS = {"server", "servername", "host", "hostname", "computer", "computername", "machine",
                     "example", "share", "localhost", "wsl", "wsl$", "?", "."}


def _v_unc(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    host = value.lower()
    return host not in _UNC_PLACEHOLDERS and not is_placeholder(host) and not host.startswith("wsl")


_INTERNAL_LINKS: List[Tuple[str, str]] = [
    ("Google Docs", r"https?://docs\.google\.com/(?:a/[^/\s]+/)?(?:document|spreadsheets|presentation|forms|drawings)/d/[A-Za-z0-9_-]{15,}"),
    ("Google Drive", r"https?://drive\.google\.com/(?:a/[^/\s]+/)?(?:file/d/|drive/(?:u/\d+/)?folders/|open\?id=)[A-Za-z0-9_-]{10,}"),
    ("Atlassian", r"https?://[a-z0-9-]+\.atlassian\.net/[^\s\"'<>)]+"),
    ("Slack", r"https?://(?:[a-z0-9-]+\.slack\.com/(?:archives|messages|team|files)/|app\.slack\.com/client/)[^\s\"'<>)]+"),
    ("Notion", r"https?://(?:www\.)?notion\.so/[^\s\"'<>)]+"),
    ("Figma", r"https?://(?:www\.)?figma\.com/(?:file|design|proto|board|slides)/[A-Za-z0-9]{10,}[^\s\"'<>)]*"),
    ("Linear", r"https?://linear\.app/[a-z0-9-]+/(?:issue|project|view)/[^\s\"'<>)]+"),
    ("Trello", r"https?://trello\.com/[bc]/[A-Za-z0-9]{6,}[^\s\"'<>)]*"),
    ("SharePoint", r"https?://[a-z0-9-]+(?:-my)?\.sharepoint\.com/[^\s\"'<>)]+"),
    ("OneDrive", r"https?://(?:onedrive\.live\.com|1drv\.ms)/[^\s\"'<>)]+"),
    ("Dropbox", r"https?://(?:www\.)?dropbox\.com/(?:s|scl|sh)/[^\s\"'<>)]+"),
    ("Airtable", r"https?://(?:www\.)?airtable\.com/(?:app|shr|tbl)[A-Za-z0-9]{10,}[^\s\"'<>)]*"),
    ("Miro", r"https?://miro\.com/app/board/[^\s\"'<>)]+"),
    ("Loom", r"https?://(?:www\.)?loom\.com/share/[^\s\"'<>)]+"),
    ("Asana", r"https?://app\.asana\.com/\d+/[^\s\"'<>)]+"),
    ("ClickUp", r"https?://app\.clickup\.com/[^\s\"'<>)]+"),
    ("Monday", r"https?://[a-z0-9-]+\.monday\.com/boards/[^\s\"'<>)]+"),
    ("Canva", r"https?://(?:www\.)?canva\.com/design/[^\s\"'<>)]+"),
    ("AWS console", r"https?://(?:[a-z0-9-]+\.)?console\.aws\.amazon\.com/[^\s\"'<>)]+"),
    ("Google Cloud console", r"https?://console\.cloud\.google\.com/[^\s\"'<>)]+"),
    ("Azure portal", r"https?://portal\.azure\.com/[^\s\"'<>)]+"),
    ("Cloudflare dashboard", r"https?://dash\.cloudflare\.com/[0-9a-f]{32}[^\s\"'<>)]*"),
    ("Meta Business Suite", r"https?://(?:business|adsmanager)\.facebook\.com/[^\s\"'<>)]+"),
    ("Google Ads", r"https?://ads\.google\.com/aw/[^\s\"'<>)]+"),
    ("App Store Connect", r"https?://appstoreconnect\.apple\.com/[^\s\"'<>)]+"),
    ("Google Play Console", r"https?://play\.google\.com/console/[^\s\"'<>)]+"),
    ("AdMob", r"https?://(?:apps\.)?admob\.google\.com/[^\s\"'<>)]+"),
    ("Google Analytics", r"https?://analytics\.google\.com/analytics/web/[^\s\"'<>)]+"),
    ("Firebase console", r"https?://console\.firebase\.google\.com/[^\s\"'<>)]+"),
]
_LINK_RX = re.compile("|".join(f"(?P<l{i}>{rx})" for i, (_, rx) in enumerate(_INTERNAL_LINKS)))


def _v_internal_link(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if is_placeholder(value) or "your" in value.lower():
        return False
    for i, (name, _) in enumerate(_INTERNAL_LINKS):
        if m.group(f"l{i}"):
            return name
    return True


def _phone_digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _v_phone(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if in_lockfile(ctx):
        return False
    digits = _phone_digits(value)
    if not 10 <= len(digits) <= 15:
        return False
    if len(set(digits)) <= 2 or looks_sequential(digits[1:]) or looks_sequential(digits[2:]):
        return False
    if digits.startswith("1") and digits[4:7] == "555":
        return False  # North American fictional numbers
    if re.fullmatch(r"\d+", value.lstrip("+")):  # no separators: must be E.164-like and quoted or prose
        return len(digits) >= 11
    return True


_TEST_CARDS = {
    "4242424242424242", "4000056655665556", "5555555555554444", "2223003122003222",
    "5200828282828210", "5105105105105100", "378282246310005", "371449635398431",
    "6011111111111117", "6011000990139424", "3056930009020004", "36227206271667",
    "3566002020360505", "6200000000000005", "4111111111111111", "4012888888881881",
    "4000002500003155",
}


def _card_network(d: str) -> bool:
    if d[0] == "4" and len(d) in (13, 16, 19):
        return True
    if len(d) == 16 and (51 <= int(d[:2]) <= 55 or 2221 <= int(d[:4]) <= 2720):
        return True
    if len(d) == 15 and d[:2] in ("34", "37"):
        return True
    if len(d) in (16, 19) and (d.startswith("6011") or d.startswith("65") or 644 <= int(d[:3]) <= 649):
        return True
    if len(d) in (16, 17, 18, 19) and 3528 <= int(d[:4]) <= 3589:
        return True
    if len(d) == 14 and (d[:2] in ("36", "38") or 300 <= int(d[:3]) <= 305):
        return True
    return len(d) in (16, 17, 18, 19) and d.startswith("62")


def _v_card(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    digits = re.sub(r"[ -]", "", value)
    if not 13 <= len(digits) <= 19 or digits in _TEST_CARDS or digits in WELL_KNOWN_NUMBERS:
        return False
    if digits in ctx.settings.allowed_numbers:
        return False
    seps = set(re.findall(r"[ -]", value))
    if len(seps) > 1:
        return False
    if seps:
        groups = [len(g) for g in re.split(r"[ -]", value)]
        if groups not in ([4, 4, 4, 4], [4, 4, 4, 4, 3], [4, 6, 5], [4, 6, 4], [4, 4, 4, 2], [4, 4, 4, 3]):
            return False
    if len(set(digits)) <= 2 or looks_sequential(digits):
        return False
    if not luhn_ok(digits) or not _card_network(digits):
        return False
    if _HASH_CONTEXT.search(ctx.before(40)) or _TIME_CONTEXT.search(ctx.before(40)):
        return False
    return True


def _v_digits_not_placeholder(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    digits = re.sub(r"\D", "", value)
    if digits and (is_placeholder_number(digits) or digits in ctx.settings.allowed_numbers):
        return False
    return not is_placeholder(value)


_BUCKET_PLACEHOLDERS = re.compile(r"example|your|my-?bucket|bucket-?name|placeholder|^bucket$|^test$|^name$|\{|<|\$", re.IGNORECASE)


def _v_bucket(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if _BUCKET_PLACEHOLDERS.search(value):
        return False
    return not is_placeholder(value)


_ID_NAME = re.compile(
    r"(?:customer|account|acct|client|business|page|app|ad[_-]?account|campaign|ad[_-]?set|adset|ad[_-]?group|"
    r"pixel|property|tenant|project|org|organization|merchant|publisher|developer|instagram|ig[_-]?user|"
    r"fb[_-]?user|user)[_-]?$",
    re.IGNORECASE,
)


def _v_identifier_assignment(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    name_end = m.start()
    head = ctx.text[max(0, name_end - 40):name_end]
    word = re.search(r"[A-Za-z_-]*$", head)
    if not word or not _ID_NAME.search(word.group()) or len(word.group()) > 30:
        return False
    if word.group() and not re.match(r"[A-Za-z]", word.group()):
        return False
    digits = sum(c.isdigit() for c in value)
    if is_placeholder(value) or value in ctx.settings.allowed_numbers:
        return False
    if re.fullmatch(r"\d+", value) and (is_placeholder_number(value) or is_round_number(value)):
        return False
    if digits >= 5:
        return True
    return bool(re.fullmatch(r"[A-Z0-9]{10}", value)) and digits >= 2 and any(c.isalpha() for c in value)


def _v_apple(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    if is_placeholder(value) or value.upper() in ("ABCDE12345", "ABC123DEFG", "TEAMID1234"):
        return False
    if re.fullmatch(r"[A-Z0-9]{10}", value):
        return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)
    return True


def _v_ad_identifier(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    digits = re.sub(r"\D", "", value)
    if digits and (is_placeholder_number(digits) or digits in ctx.settings.allowed_numbers):
        return False
    if value.startswith(("G-", "GTM-", "GT-")):
        tail = value.split("-", 1)[1]
        if not (any(c.isdigit() for c in tail) and any(c.isalpha() for c in tail)):
            return False
    return not is_placeholder(value)


def _v_confidential(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
    return True


# ---------------------------------------------------------------------------
# Rule table


def _rx(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


def _content_rules(s: Settings) -> List[Rule]:
    n = max(6, s.numeric_id_min_length)
    rules: List[Rule] = [
        # --- secrets -------------------------------------------------------
        Rule("secret.private-key", "Private key", "error",
             "A PEM, OpenSSH, PGP or PuTTY private key block. Anyone holding it can impersonate the key owner.",
             "Remove the key, revoke or rotate it, and load keys from a secret store at runtime.",
             _rx(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY(?: BLOCK)?-----|PuTTY-User-Key-File-[23]: "),
             keywords=("private key", "putty-user-key-file"), targets=SECRETS, validate=_v_private_key,
             priority=200),
        Rule("secret.aws-access-key-id", "AWS access key ID", "error",
             "An AWS access key ID (AKIA/ASIA...). Usually published together with its secret key.",
             "Deactivate the key in IAM, check CloudTrail for use, and switch to short-lived credentials.",
             _rx(r"(?<![A-Za-z0-9])((?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16})(?![A-Za-z0-9])"),
             group=1, keywords=("akia", "asia", "abia", "acca", "a3t"), targets=SECRETS | {PATH},
             validate=_v_aws_key_id, priority=200),
        Rule("secret.aws-secret-access-key", "AWS secret access key", "error",
             "A 40-character AWS secret access key assigned to an aws_secret_access_key-style name.",
             "Deactivate the key pair in IAM and rotate it.",
             _rx(r"(?i:(?:aws_?)?secret_?access_?key|aws_?secret_?key|aws_?secret)[\"']?\s*(?:[:=]|=>)\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"),
             group=1, keywords=("secret",), targets=SECRETS, validate=_entropy_at_least(3.5), priority=200),
        Rule("secret.github-token", "GitHub token", "error",
             "A GitHub personal access, OAuth, app or refresh token.",
             "Revoke it at github.com/settings/tokens (or the app settings) and create a new one.",
             _rx(r"(?<![A-Za-z0-9_])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})(?![A-Za-z0-9_])"),
             group=1, keywords=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"), targets=SECRETS,
             validate=_not_placeholder, priority=200),
        Rule("secret.gitlab-token", "GitLab token", "error",
             "A GitLab personal, project, deploy, runner or trigger token.",
             "Revoke the token in GitLab and create a new one.",
             _rx(r"(?<![A-Za-z0-9_-])(gl(?:pat|ptt|dt|rt|cbt|soat|ffct)-[A-Za-z0-9_-]{20,})"),
             group=1, keywords=("glpat-", "glptt-", "gldt-", "glrt-", "glcbt-", "glsoat-", "glffct-"),
             targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.google-api-key", "Google API key", "error",
             "A Google API key (AIza...). Browser keys for Maps or Firebase are meant to ship, but only with "
             "application restrictions; unrestricted keys are abused for billing.",
             "Restrict or rotate the key in Google Cloud console; allow it here only if it is a restricted browser key.",
             _rx(r"(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])"),
             group=1, keywords=("aiza",), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.google-oauth-token", "Google OAuth token", "error",
             "A Google OAuth access token (ya29.) or refresh token (1//0...).",
             "Revoke the grant at myaccount.google.com/permissions or in the OAuth client, then rotate.",
             _rx(r"(?<![A-Za-z0-9_-])(ya29\.[0-9A-Za-z_-]{20,}|1//0[0-9A-Za-z_-]{30,})"),
             group=1, keywords=("ya29.", "1//0"), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.google-oauth-client-secret", "Google OAuth client secret", "error",
             "A Google OAuth client secret (GOCSPX-...).",
             "Reset the client secret in Google Cloud console.",
             _rx(r"(?<![A-Za-z0-9_-])(GOCSPX-[0-9A-Za-z_-]{28})(?![A-Za-z0-9_-])"),
             group=1, keywords=("gocspx-",), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.meta-access-token", "Meta access token", "error",
             "A Meta (Facebook/Instagram) Graph API access token (EAA...).",
             "Invalidate it (change the app secret or remove the system user token) and issue a new one.",
             _rx(r"(?<![A-Za-z0-9+/])(EAA[A-Za-z0-9]{40,})(?![A-Za-z0-9+/=])"),
             group=1, keywords=("eaa",), targets=SECRETS, validate=_entropy_at_least(4.0), priority=200),
        Rule("secret.meta-app-token", "Meta app access token", "error",
             "A Meta app access token in app-id|app-secret form.",
             "Reset the app secret in the Meta developer dashboard.",
             _rx(r"(?<![0-9])(\d{15,17}(?:\||%7[Cc])[A-Za-z0-9_-]{27,43})(?![A-Za-z0-9_-])"),
             group=1, keywords=("|", "%7c"), targets=SECRETS, validate=_entropy_at_least(3.5), priority=200),
        Rule("secret.slack-token", "Slack token", "error",
             "A Slack bot, user, app or configuration token.",
             "Revoke it in the Slack app settings and create a new one.",
             _rx(r"(?<![A-Za-z0-9])(xox[abposre]-(?:\d+-)?[0-9A-Za-z-]{10,}|xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+)"),
             group=1, keywords=("xox", "xapp-"), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.slack-webhook", "Slack webhook URL", "error",
             "A Slack incoming-webhook or workflow URL; anyone with it can post to your workspace.",
             "Delete the webhook in Slack and create a new one.",
             _rx(r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{20,})"),
             group=1, keywords=("hooks.slack.com",), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.stripe-live-key", "Stripe live secret key", "error",
             "A Stripe live secret or restricted key.",
             "Roll the key in the Stripe dashboard.",
             _rx(r"(?<![A-Za-z0-9])((?:sk|rk)_live_[0-9A-Za-z]{20,})(?![A-Za-z0-9])"),
             group=1, keywords=("sk_live_", "rk_live_"), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.stripe-test-key", "Stripe test secret key", "warning",
             "A Stripe test-mode secret key: no money moves, but it opens your test data and settings.",
             "Roll the test key in the Stripe dashboard.",
             _rx(r"(?<![A-Za-z0-9])((?:sk|rk)_test_[0-9A-Za-z]{20,})(?![A-Za-z0-9])"),
             group=1, keywords=("sk_test_", "rk_test_"), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.stripe-webhook-secret", "Stripe webhook signing secret", "error",
             "A Stripe webhook signing secret (whsec_...).",
             "Roll the signing secret for the endpoint in the Stripe dashboard.",
             _rx(r"(?<![A-Za-z0-9])(whsec_[0-9A-Za-z]{24,})(?![A-Za-z0-9])"),
             group=1, keywords=("whsec_",), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.npm-token", "npm access token", "error",
             "An npm automation, publish or read token (npm_...).",
             "Revoke it with 'npm token revoke' or on npmjs.com.",
             _rx(r"(?<![A-Za-z0-9])(npm_[A-Za-z0-9]{36})(?![A-Za-z0-9])"),
             group=1, keywords=("npm_",), targets=SECRETS, validate=_entropy_at_least(3.5), priority=200),
        Rule("secret.pypi-token", "PyPI API token", "error",
             "A PyPI upload token (pypi-AgEIcHlwaS5vcmc...).",
             "Delete the token in your PyPI account settings.",
             _rx(r"(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})"),
             group=1, keywords=("pypi-ageichlwas5vcmc",), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.openai-api-key", "OpenAI API key", "error",
             "An OpenAI API key (sk-... with the T3BlbkFJ marker, or a long sk-proj- key).",
             "Revoke the key in the OpenAI dashboard.",
             _rx(r"(?<![A-Za-z0-9_-])(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}|sk-proj-[A-Za-z0-9_-]{80,})"),
             group=1, keywords=("t3blbkfj", "sk-proj-"), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.anthropic-api-key", "Anthropic API key", "error",
             "An Anthropic API or admin key (sk-ant-...).",
             "Revoke the key in the Anthropic Console.",
             _rx(r"(?<![A-Za-z0-9_-])(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})"),
             group=1, keywords=("sk-ant-",), targets=SECRETS, validate=_not_placeholder, priority=200),
        Rule("secret.jwt", "JSON Web Token", "error",
             "A signed JSON Web Token. Many are session or service credentials, some long-lived.",
             "Find out what issued it; revoke the session or rotate the signing key if it is still valid.",
             _rx(r"(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)"),
             group=1, keywords=("eyj",), targets=SECRETS, validate=_v_jwt, priority=200),
        Rule("secret.credentials-in-url", "Password in a URL", "error",
             "A URL with an embedded user:password@host credential.",
             "Change the password and pass credentials through environment variables or a secret store.",
             _rx(r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/?#@\"'<>`]{1,64}:([^\s/?#@\"'<>`]{1,128})@[A-Za-z0-9.-]+"),
             group=1, keywords=("://",), targets=SECRETS, validate=_v_url_password, priority=200),
        Rule("secret.authorization-header", "Authorization header credential", "error",
             "A literal HTTP Authorization header with Basic credentials or a bearer token.",
             "Rotate the credential; keep headers out of logs, fixtures and docs.",
             _rx(r"(?i:\bauthorization)[\"']?\s*[:=]\s*[\"']?(?P<scheme>(?i:basic|bearer|token))\s+([A-Za-z0-9._~+/=-]{16,})"),
             group=2, keywords=("authorization",), targets=SECRETS, validate=_v_basic_auth, priority=200),
        Rule("secret.generic-assignment", "Hard-coded credential", "warning",
             "A quoted value assigned to a name such as password, secret, token or api_key.",
             "Move the value to an environment variable or secret store; if it is a fake, allow it in config.",
             _rx(r"(?i:secret|token|passwd|password|pwd|api[_-]?key|apikey|access[_-]?key|auth[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.-]{0,40}[\"']?\s*(?::=|=>|[:=])\s*(?P<q>[\"'`])([^\"'`\s]{8,200})(?P=q)"),
             group=2, keywords=("secret", "token", "passw", "pwd", "key", "credential"),
             targets=frozenset({TEXT, COMMIT, DECODED}), validate=_v_generic_assignment, priority=90),
        Rule("secret.high-entropy-string", "High-entropy string", "warning",
             "A long random-looking token (mixed case and digits, entropy above the threshold) that may be a credential.",
             "Check what it is. Rotate it if it is a credential; otherwise allow it in config.",
             _rx(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{%d,}={0,2})(?![A-Za-z0-9+/=_-])" % max(8, s.entropy_min_length)),
             group=1, targets=frozenset({TEXT}), validate=_v_entropy, priority=40),
        # --- leaks ---------------------------------------------------------
        Rule("leak.home-path", "Absolute home-directory path", "warning",
             "An absolute path inside a user's home directory (/Users/<name>, /home/<name>, C:\\Users\\<name>). "
             "It reveals a username and the layout of a developer's machine.",
             "Use relative paths, ~, or an environment variable.",
             _rx(r"(?<![A-Za-z0-9_.-])(?:/mnt/[a-z])?/(?P<base>Users|home)/(?P<uname>[A-Za-z0-9_][^/\s\"'`<>()\[\]{}:;,|*?\\]*)(?P<rest>/[^\s\"'`<>|]*)?"
                 r"|(?<![A-Za-z0-9])[A-Za-z]:(?:\\\\|\\|/)(?:Users|Documents and Settings)(?:\\\\|\\|/)(?P<wname>[A-Za-z0-9_][^\\/\s\"'`<>|:*?]*)"),
             keywords=("/users/", "/home/", ":\\users", ":/users", ":\\\\users", "documents and settings"),
             targets=ALL, validate=_v_home_path, priority=80),
        Rule("leak.mounted-volume", "Mounted volume path", "warning",
             "A macOS /Volumes/<name> path: it names a disk on a developer's machine.",
             "Use relative paths or a configurable location.",
             _rx(r"(?<![A-Za-z0-9_.-])/Volumes/([A-Za-z0-9][^/\s\"'`<>|]*)"),
             keywords=("/volumes/",), targets=ALL, validate=_v_volume, priority=80),
        Rule("leak.email", "Email address", "warning",
             "An email address outside the allowed domains. Addresses of staff and customers are personal data "
             "and attract spam and phishing.",
             "Remove it, use a role address on an allowed domain, or add the domain to allowed-email-domains.",
             _rx(r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])"),
             group=1, keywords=("@",), targets=frozenset({TEXT, PATH, META, COMMIT, REF, DECODED}),
             validate=_v_email, priority=80),
        Rule("leak.numeric-id", "Long numeric identifier", "warning",
             f"A standalone number of {n}+ digits: account, customer, campaign, page or user IDs usually look like this.",
             "Move IDs to configuration that is not published, or allow placeholders in config.",
             _rx(r"(?<![0-9])(\d{%d,})(?![0-9])" % n),
             group=1, targets=frozenset({TEXT, PATH, META, COMMIT, REF}), validate=_v_numeric_id, priority=50),
        Rule("leak.ip-address", "IP address", "warning",
             "A private, shared (VPN/tailnet) or public IP address of a host. Documentation ranges, loopback and "
             "well-known public resolvers are ignored.",
             "Replace it with a hostname from configuration or a documentation address (192.0.2.0/24).",
             _rx(r"(?<![\w.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\w)(?!\.\d)"
                 r"|(?<![\w:.])((?:[0-9A-Fa-f]{1,4})?(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:])"),
             group=-1, targets=frozenset({TEXT, META, COMMIT}), validate=_v_ip, priority=80),
        Rule("leak.internal-host", "Internal hostname", "warning",
             "A hostname on an internal-only suffix (.internal, .corp, .lan, .local, .home.arpa...) or a UNC path.",
             "Use a placeholder host such as db.example.internal, or read the host from configuration.",
             _rx(r"(?<![A-Za-z0-9.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:internal|intranet|corp|lan|local|localdomain|home\.arpa|priv))(?![A-Za-z0-9-]|\.[A-Za-z])"),
             group=1, keywords=(".internal", ".intranet", ".corp", ".lan", ".local", ".home.arpa", ".priv"),
             targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}), validate=_v_internal_host, priority=80),
        Rule("leak.internal-host", "Internal hostname", "warning",
             "A hostname on an internal-only suffix (.internal, .corp, .lan, .local, .home.arpa...) or a UNC path.",
             "Use a placeholder host such as db.example.internal, or read the host from configuration.",
             _rx(r"(?<![\\\w])\\\\([A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]+)*)\\[A-Za-z0-9$_.-]+"),
             group=1, keywords=("\\\\",), targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}),
             validate=_v_unc, priority=80),
        Rule("leak.internal-link", "Link to a private workspace or console", "warning",
             "A link into a private workspace or admin console (Google Docs/Drive, Slack, Notion, Jira, Figma, "
             "cloud, ads and store consoles...). Such links often carry account IDs and internal names.",
             "Remove the link or replace it with public documentation.",
             _LINK_RX, targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}),
             keywords=("docs.google", "drive.google", "atlassian.net", "slack.com", "notion.so", "figma.com",
                       "linear.app", "trello.com", "sharepoint.com", "onedrive", "1drv.ms", "dropbox.com",
                       "airtable.com", "miro.com", "loom.com", "asana.com", "clickup.com", "monday.com",
                       "canva.com", "console.aws", "console.cloud.google", "portal.azure", "dash.cloudflare",
                       "facebook.com", "ads.google", "appstoreconnect.apple", "play.google.com/console",
                       "admob.google", "analytics.google", "console.firebase"),
             validate=_v_internal_link, priority=150),
        Rule("leak.confidential-marker", "Confidentiality marking", "warning",
             "Text carrying a confidentiality marking: a confidential or internal-use stamp, a "
             "do-not-distribute line or an NDA notice. Marked material should not be published.",
             "Remove the material or get it cleared for publication.",
             _rx(r"\b(?:STRICTLY CONFIDENTIAL|COMPANY CONFIDENTIAL|CONFIDENTIAL|INTERNAL USE ONLY|INTERNAL ONLY)\b"  # prepublish-audit:allow leak.confidential-marker
                 r"|(?i:\binternal use only\b|\bdo not (?:distribute|forward|redistribute)\b|"  # prepublish-audit:allow leak.confidential-marker
                 r"\bnot for (?:public )?(?:release|distribution)\b|\bproprietary and confidential\b|\bunder (?:an )?NDA\b)"),
             keywords=("confidential", "internal use", "internal only", "do not distribute", "do not forward",  # prepublish-audit:allow leak.confidential-marker
                       "do not redistribute", "not for release", "not for public", "not for distribution",  # prepublish-audit:allow leak.confidential-marker
                       "under nda", "under an nda"),  # prepublish-audit:allow leak.confidential-marker
             targets=frozenset({TEXT, BINARY, META, COMMIT}), validate=_v_confidential, priority=80),
        Rule("leak.phone-number", "Phone number", "warning",
             "An international phone number (+country code). Staff and customer numbers are personal data.",
             "Remove it or use a fictional number.",
             _rx(r"(?<![\w+])\+[1-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,5}(?![\w])"),
             keywords=("+",), targets=frozenset({TEXT, META, COMMIT}), validate=_v_phone, priority=80),
        Rule("leak.payment-card", "Payment card number", "error",
             "A Luhn-valid number with a card-network prefix. Public test cards are ignored.",
             "Remove it; if it is real, treat it as a card data incident.",
             _rx(r"(?<![\d.-])(\d(?:[ -]?\d){12,18})(?![\d.-])"),
             group=1, targets=frozenset({TEXT, META, COMMIT, BINARY}), validate=_v_card, priority=150),
        Rule("leak.cloud-account-id", "Cloud account ID", "warning",
             "An AWS account ID inside an ARN.",
             "Use a placeholder account such as 123456789012 in examples.",
             _rx(r"\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):"),
             group=1, keywords=("arn:aws",), targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}),
             validate=_v_digits_not_placeholder, priority=150),
        Rule("leak.cloud-resource", "Cloud resource name", "warning",
             "A storage bucket (S3, GCS, R2, Azure Blob) or an AWS resource ID such as an EC2 instance.",
             "Read resource names from configuration; use placeholders in docs.",
             _rx(r"\bs3://([a-z0-9][a-z0-9.-]{2,62})"
                 r"|\bgs://([a-z0-9][a-z0-9._-]{2,62})"
                 r"|https?://([a-z0-9][a-z0-9.-]{2,62})\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com"
                 r"|https?://s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]{2,62})"
                 r"|https?://storage\.googleapis\.com/([a-z0-9][a-z0-9._-]{2,62})"
                 r"|https?://([a-z0-9-]{3,63})\.r2\.cloudflarestorage\.com"
                 r"|https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net"),
             group=-1, keywords=("s3://", "gs://", "amazonaws.com", "storage.googleapis.com",
                                 "r2.cloudflarestorage.com", "blob.core.windows.net"),
             targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}), validate=_v_bucket, priority=150),
        Rule("leak.cloud-resource", "Cloud resource name", "warning",
             "A storage bucket (S3, GCS, R2, Azure Blob) or an AWS resource ID such as an EC2 instance.",
             "Read resource names from configuration; use placeholders in docs.",
             _rx(r"\b((?:i|vpc|subnet|sg|ami|vol|snap|eni|igw|rtb|nat|eipalloc|acl|lt)-[0-9a-f]{17})\b"),
             group=1, targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}), validate=_v_bucket, priority=150),
        Rule("leak.ad-identifier", "Advertising or analytics account ID", "warning",
             "An AdMob/AdSense publisher or app ID, a Google Ads conversion ID, a Meta ad account (act_...) "
             "or a Google tag ID.",
             "Keep ad and analytics IDs in build configuration that is not published.",
             _rx(r"\b(ca-app-pub-\d{16}(?:[~/]\d{10})?|pub-\d{16}|AW-\d{9,11}(?:/[A-Za-z0-9_-]{6,})?|act_\d{6,20}"
                 r"|G-[A-Z0-9]{8,12}|UA-\d{4,10}-\d{1,4}|GTM-[A-Z0-9]{5,8}|GT-[A-Z0-9]{6,9})\b"),
             group=1, keywords=("ca-app-pub-", "pub-", "aw-", "act_", "g-", "ua-", "gtm-", "gt-"),
             targets=frozenset({TEXT, BINARY, META, COMMIT, DECODED}), validate=_v_ad_identifier, priority=150),
        Rule("leak.apple-developer-id", "Apple developer account ID", "warning",
             "An Apple team ID, App Store Connect key ID or issuer ID, or an AuthKey_<KEYID>.p8 file name.",
             "Keep team and key IDs in local build settings or CI secrets.",
             _rx(r"\bDEVELOPMENT_TEAM\s*=\s*\"?([A-Z0-9]{10})\b"
                 r"|(?i:\bteam[_-]?id(?:entifier)?\b)[\"'>\s]*(?:[:=]|</key>\s*<string>|</key>\s*<array>\s*<string>)\s*[\"']?([A-Z0-9]{10})\b"
                 r"|(?i:\b(?:asc|app[_-]?store[_-]?connect|api)?[_-]?key[_-]?id\b)[\"']?\s*[:=]\s*[\"']?([A-Z0-9]{10})\b"
                 r"|(?i:\bissuer(?:[_-]?id)?\b)[\"']?\s*[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b"
                 r"|\bAuthKey_([A-Z0-9]{10})\.p8\b"),
             group=-1, keywords=("development_team", "teamid", "team_id", "team-id", "teamidentifier",
                                 "team-identifier", "team_identifier", "keyid", "key_id", "key-id", "issuer",
                                 "authkey_"),
             targets=frozenset({TEXT, PATH, BINARY, META, COMMIT}), validate=_v_apple, priority=150),
        Rule("leak.identifier-assignment", "Hard-coded account identifier", "warning",
             "A value assigned to a name such as customer_id, account_id, page_id or business_id.",
             "Read the ID from configuration that is not published.",
             _rx(r"(?i:id)\b[\"']?\s*(?::=|=>|[:=])\s*[\"']?([A-Za-z0-9][A-Za-z0-9-]{4,40})\b"),
             group=1, keywords=("id",), targets=frozenset({TEXT, META, COMMIT, DECODED}),
             validate=_v_identifier_assignment, priority=60),
    ]
    for i, ip in enumerate(s.internal_patterns, 1):
        rules.append(Rule(
            "leak.internal-name", "Internal name pattern", "warning",
            "A name that matches one of your internal-name patterns from the config.",
            "Rename it or remove it before publishing.",
            ip.regex, 0, (), ALL, _labelled(ip.label), 80))
    return rules


def _labelled(label: str) -> Validator:
    def check(value: str, m: "re.Match[str]", ctx: RuleContext) -> Verdict:
        return label
    return check


# ---------------------------------------------------------------------------
# File rules

@dataclass(frozen=True)
class FileRule:
    id: str
    severity: str
    detail: str
    match: Callable[[str], bool]


def _base(path: str) -> str:
    return path.rsplit("/", 1)[-1]


_ENV_OK = re.compile(r"\.env\.(?:example|sample|template|dist|defaults?|schema|test\.example)$", re.IGNORECASE)


def _is_env(path: str) -> bool:
    b = _base(path).lower()
    return (b == ".env" or b.startswith(".env.") or b.endswith(".env")) and not _ENV_OK.search(b) and b != ".envrc"


def _ext(path: str, *exts: str) -> bool:
    return _base(path).lower().endswith(tuple(exts))


FILE_RULES: Tuple[FileRule, ...] = (
    FileRule("secret.sensitive-file", "error", "App Store Connect / APNs API private key (.p8)",
             lambda p: _ext(p, ".p8")),
    FileRule("secret.sensitive-file", "error", "PKCS#12 certificate bundle with a private key",
             lambda p: _ext(p, ".p12", ".pfx")),
    FileRule("secret.sensitive-file", "error", "Java/Android signing keystore",
             lambda p: _ext(p, ".jks", ".keystore", ".bks")),
    FileRule("secret.sensitive-file", "error", "SSH private key",
             lambda p: _base(p) in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk")),
    FileRule("secret.sensitive-file", "error", "Terraform state (contains secrets in plain text)",
             lambda p: _ext(p, ".tfstate", ".tfstate.backup")),
    FileRule("secret.sensitive-file", "error", "credentials file",
             lambda p: _base(p) in (".netrc", "_netrc", ".pgpass", ".git-credentials", ".htpasswd")
             or p.endswith(".aws/credentials") or p.endswith(".docker/config.json")),
    FileRule("secret.sensitive-file", "error", "password manager database",
             lambda p: _ext(p, ".kdbx", ".kdb", ".1pif", ".agilekeychain", ".opvault")),
    FileRule("secret.sensitive-file", "warning", "environment file (usually holds secrets)", _is_env),
    FileRule("secret.sensitive-file", "warning", "Apple provisioning profile (team, certificates and device IDs)",
             lambda p: _ext(p, ".mobileprovision", ".provisionprofile")),
    FileRule("secret.sensitive-file", "warning", "Terraform variables file",
             lambda p: _ext(p, ".tfvars", ".tfvars.json") and not _ext(p, ".example.tfvars")),
    FileRule("secret.sensitive-file", "warning", "package-manager credentials file",
             lambda p: _base(p) in (".npmrc", ".pypirc", ".yarnrc.yml") or p.endswith(".gem/credentials")),
    FileRule("secret.sensitive-file", "warning", "VPN or kubeconfig file",
             lambda p: _ext(p, ".ovpn", ".kubeconfig") or _base(p) == "kubeconfig"),
    FileRule("leak.os-metadata-file", "warning", "Finder metadata (.DS_Store lists file names)",
             lambda p: _base(p) == ".DS_Store"),
    FileRule("leak.os-metadata-file", "warning", "macOS resource fork or archive artefact",
             lambda p: _base(p).startswith("._") or p.startswith("__MACOSX/") or "/__MACOSX/" in p),
    FileRule("leak.os-metadata-file", "warning", "Windows thumbnail or folder metadata",
             lambda p: _base(p).lower() in ("thumbs.db", "ehthumbs.db", "desktop.ini")),
    FileRule("leak.os-metadata-file", "warning", "per-user IDE state (contains the username or local paths)",
             lambda p: "xcuserdata/" in p or _ext(p, ".xcuserstate") or p.endswith(".idea/workspace.xml")),
    FileRule("leak.os-metadata-file", "warning", "editor swap or lock file",
             lambda p: _ext(p, ".swp", ".swo") or _base(p).startswith(".~lock.") or _base(p).startswith("~$")),
)


# ---------------------------------------------------------------------------
# Catalogue of rules produced elsewhere

_OTHER: Tuple[Tuple[str, str, str, str, str], ...] = (
    ("denylist", "Private denylist match", "error",
     "Text that matches an entry in your private denylist. The entry is never printed; reports show its label or number.",
     "Remove or rename it. If it is allowed in this place, add an indented 'allow:' line under the entry."),
    ("secret.sensitive-file", "Sensitive file type", "error",
     "A file whose name or extension marks it as a key, credential store or secrets file.",
     "Remove the file from the tree and its history; rotate anything it contained."),
    ("leak.os-metadata-file", "Operating-system or IDE metadata file", "warning",
     "A .DS_Store, resource fork, thumbnail cache or per-user IDE file. They leak file names, usernames and local paths.",
     "Delete it and add the pattern to .gitignore (or your packaging excludes)."),
    ("leak.internal-name", "Internal name pattern", "warning",
     "A name that matches one of the internal-name patterns in your config (internal-patterns).",
     "Rename it or remove it before publishing."),
    ("leak.embedded-git-dir", "Embedded .git directory", "warning",
     "A .git directory inside the published tree or archive ships the complete history of that repository.",
     "Remove the .git directory from the bundle."),
    ("metadata.author", "Author or owner metadata", "warning",
     "Document, image or media metadata that names a person, organisation or computer (author, artist, "
     "last modified by, company, camera owner, host computer...).",
     "Strip metadata (exiftool -all=, or 'Inspect Document' in Office) or set a neutral author."),
    ("metadata.location", "Location metadata", "error",
     "GPS coordinates or a location tag in an image or video. It can reveal a home or office address.",
     "Strip location data (exiftool -gps:all= -xmp:geotag= -keys:location=) before publishing."),
    ("metadata.serial", "Device serial number", "warning",
     "A camera or lens serial number in image metadata.",
     "Strip maker and serial metadata before publishing."),
    ("git.author-identity", "Personal email in commit history", "warning",
     "A commit, tag or author email that is not a no-reply address. Public history keeps it forever.",
     f"Publish from a fresh history committed with a no-reply address (see {doc_url('docs/release-checklist.md')})."),
    ("git.shallow-clone", "Shallow clone: history scan incomplete", "warning",
     "The repository is a shallow clone, so older commits were not scanned.",
     "Fetch the full history (actions/checkout with fetch-depth: 0) and scan again."),
    ("config.denylist-in-tree", "Private denylist inside the scanned tree", "error",
     "The private denylist file sits inside a tree you are about to publish.",
     "Move the denylist outside every repository, for example to ~/.config/prepublish-audit/."),
    ("scan.incomplete", "File could not be fully scanned", "warning",
     "The scanner could not inspect this content (too large, unreadable, encrypted or an unsupported container).",
     "Check it by hand, raise the limit, or exclude it explicitly if it is safe."),
)


def catalogue(settings: Settings) -> Dict[str, Rule]:
    """Every rule the scanner can report, keyed by id."""
    rules: Dict[str, Rule] = {}
    for rule in _content_rules(settings):
        rules.setdefault(rule.id, rule)
    for rid, title, severity, description, remediation in _OTHER:
        rules.setdefault(rid, Rule(rid, title, severity, description, remediation, kind="other", priority=300 if rid == "denylist" else 150))
    return rules


def content_rules(settings: Settings) -> List[Rule]:
    return [r for r in _content_rules(settings) if not settings.rule_disabled(r.id)]


def gitleaks_rule(rule_id: str) -> Rule:
    return Rule(
        f"gitleaks.{rule_id}", f"gitleaks: {rule_id}", "error",
        f"Reported by gitleaks rule '{rule_id}'.",
        "Rotate the credential and remove it from the tree and history.",
        kind="other", priority=190,
    )
