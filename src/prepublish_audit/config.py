"""Public, per-repository settings.

The config file ships with your repository, so it must never hold private
values. Private strings belong in the denylist. The config tunes heuristics,
excludes paths and allows known-good findings of the built-in rules.

Anyone who can change the repository can change this file, so it is treated
as untrusted where the denylist is concerned:

* it cannot disable, allow or re-grade denylist matches, nor the coverage
  rules (``scan.*``, ``config.*``, ``git.shallow-clone``) that say what could
  not be checked; only the command line can;
* ``fail-on = "never"`` is accepted only on the command line;
* when a denylist is loaded, paths it excludes are still checked against the
  denylist (and nothing else), and values that would shrink what is read
  (smaller size or depth limits, ``decode``, ``archives`` or
  ``external-tools`` turned off) are not applied. See
  :meth:`Settings.keep_denylist_coverage`.

Discovery (first match wins), starting at the scanned directory and walking up
until a directory that contains ``.git`` or the filesystem root:

* ``.prepublish-audit.toml``
* ``prepublish-audit.toml``
* ``.prepublish-audit.json``
* ``pyproject.toml`` with a ``[tool.prepublish-audit]`` table
"""

from __future__ import annotations

import itertools
import json
import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Sequence, Set, Tuple

from . import tomlcompat
from .globs import GlobSet
from .util import parse_size

CONFIG_NAMES = (".prepublish-audit.toml", "prepublish-audit.toml", ".prepublish-audit.json")

DEFAULT_EXCLUDED_DIRS = (
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
)

DEFAULT_ALLOWED_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example.edu",
    "example",
    "test",
    "invalid",
    "localhost",
    "users.noreply.github.com",
    # obvious documentation placeholders
    "domain.com",
    "yourdomain.com",
    "your-domain.com",
    "yourcompany.com",
    "your-company.com",
    "mycompany.com",
    "company.com",
)

DEFAULT_ALLOWED_EMAILS = (
    "git@github.com",
    "git@gitlab.com",
    "git@bitbucket.org",
    "git@ssh.dev.azure.com",
    "noreply@github.com",
)

# The commit identity check only accepts these by default (plus your own
# allowed domains): an address in a public history is public forever.
DEFAULT_GIT_IDENTITY_DOMAINS = ("users.noreply.github.com",)
DEFAULT_GIT_IDENTITY_EMAILS = ("noreply@github.com",)

DEFAULT_ALLOWED_HOME_USERS = (
    "runner",
    "runneradmin",
    "user",
    "username",
    "user_name",
    "you",
    "yourname",
    "your_name",
    "your-name",
    "youruser",
    "yourusername",
    "me",
    "name",
    "example",
    "shared",
    "guest",
    "ubuntu",
    "ec2-user",
    "admin",
    "root",
    "vagrant",
    "docker",
    "node",
    "app",
    "jenkins",
    "circleci",
    "travis",
    "nobody",
    "linuxbrew",
    "vscode",
    "codespace",
    "gitpod",
    "coder",
    "ci",
    "build",
    "builder",
    "public",
    "default",
    "all users",
)

DEFAULT_ALLOWED_HOSTS = (
    "host.docker.internal",
    "gateway.docker.internal",
    "kubernetes.docker.internal",
    "metadata.google.internal",
    "localhost.localdomain",
    "kubernetes.default.svc.cluster.local",
)

DEFAULT_ALLOWED_IPS = (
    "0.0.0.0",
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "169.254.169.254",
    "10.0.0.0",
    "10.0.0.1",
    "172.16.0.0",
    "192.168.0.0",
    "192.168.0.1",
    "192.168.1.0",
    "192.168.1.1",
)

_SEVERITY_NAMES = ("error", "warning", "note")
_FAIL_ON = ("error", "warning", "note", "never")
_GITLEAKS = ("auto", "always", "never")

# Findings that say what could not be checked. When a denylist is loaded they
# fail the run at "warning" level unless --fail-on is given on the command line.
COVERAGE_RULES = ("scan.incomplete", "git.shallow-clone")

# Rule-ID prefixes the public config may not name in disable, severity or allow.
_PROTECTED_PREFIXES = ("denylist", "scan", "config", "git.shallow")


def is_protected(rule_id: str) -> bool:
    """Rules that only the command line can disable, allow or re-grade.

    The denylist cannot be weakened at all; the coverage rules (``scan.*``,
    ``config.*``, ``git.shallow-clone``) can be, but only on the command line.
    Wildcards in the public config (``*``, ``s*``...) never match them.
    """
    return rule_id == "denylist" or rule_id.startswith(("scan.", "config.")) or rule_id in COVERAGE_RULES


class ConfigError(ValueError):
    pass


@dataclass
class AllowRule:
    """Allow findings of built-in rules in a known-good place."""

    rules: List[str] = field(default_factory=list)
    paths: Optional[GlobSet] = None
    line: Optional[Pattern[str]] = None
    values: Set[str] = field(default_factory=set)
    reason: str = ""
    cli: bool = False
    """True for --allow on the command line, the only source that may allow coverage rules."""

    def matches(self, rule_id: str, path: Optional[str], line: Optional[str],
                value: Optional[str]) -> bool:
        if self.rules and not any(fnmatchcase(rule_id, r) for r in self.rules):
            return False
        if self.paths is not None and (path is None or not self.paths.match(path)):
            return False
        if self.line is not None and (line is None or not self.line.search(line)):
            return False
        if self.values and (value is None or value.lower() not in self.values):
            return False
        return True


@dataclass
class InternalPattern:
    label: str
    regex: Pattern[str]


@dataclass
class Settings:
    exclude: List[str] = field(default_factory=list)
    """Excludes from the public config. With a denylist loaded these paths are
    still checked against the denylist (and only against it)."""
    cli_exclude: List[str] = field(default_factory=list)
    """Excludes from the command line: skipped completely."""
    default_excludes: bool = True
    max_file_size: int = 32 * 1024 * 1024
    max_archive_size: int = 1024 * 1024 * 1024
    max_archive_depth: int = 3
    fail_on: str = "warning"
    fail_on_cli: bool = False
    """True when --fail-on was given on the command line."""
    disable: List[str] = field(default_factory=list)
    cli_disable: List[str] = field(default_factory=list)
    severity: Dict[str, str] = field(default_factory=dict)
    allow: List[AllowRule] = field(default_factory=list)
    numeric_id_min_length: int = 10
    allowed_email_domains: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_EMAIL_DOMAINS))
    allowed_emails: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_EMAILS))
    allowed_numbers: List[str] = field(default_factory=list)
    allowed_hosts: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS))
    allowed_ips: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_IPS))
    allowed_home_users: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_HOME_USERS))
    git_identity_domains: List[str] = field(default_factory=lambda: list(DEFAULT_GIT_IDENTITY_DOMAINS))
    git_identity_emails: List[str] = field(default_factory=lambda: list(DEFAULT_GIT_IDENTITY_EMAILS))
    entropy_threshold: float = 4.3
    entropy_min_length: int = 24
    internal_patterns: List[InternalPattern] = field(default_factory=list)
    loose_denylist: bool = False
    decode: bool = True
    archives: bool = True
    external_tools: bool = True
    gitleaks: str = "auto"
    config_path: Optional[Path] = None
    config_keys: Set[str] = field(default_factory=set)
    """Top-level keys (snake_case) that the public config set."""
    cli_keys: Set[str] = field(default_factory=set)
    """Settings that a command-line option set; they win over the config."""

    # -- helpers -----------------------------------------------------------
    def rule_disabled(self, rule_id: str) -> bool:
        patterns = self.cli_disable if is_protected(rule_id) else itertools.chain(self.disable, self.cli_disable)
        return any(fnmatchcase(rule_id, pattern) for pattern in patterns)

    def severity_for(self, rule_id: str, default: str) -> str:
        if is_protected(rule_id):
            return default
        for pattern, level in self.severity.items():
            if fnmatchcase(rule_id, pattern):
                return level
        return default

    def is_allowed(self, rule_id: str, path: Optional[str], line: Optional[str],
                   value: Optional[str]) -> bool:
        protected = is_protected(rule_id)
        return any(a.matches(rule_id, path, line, value) for a in self.allow if a.cli or not protected)

    def keep_denylist_coverage(self) -> List[str]:
        """Undo public-config values that would shrink what the denylist sees.

        Called when a denylist is loaded. A smaller max-file-size,
        max-archive-size or max-archive-depth than the default, and decode,
        archives or external-tools turned off, are not applied when they come
        from the public config; command-line options still are. Returns the
        names of the settings that were not applied.
        """
        defaults = Settings()
        ignored = []
        for key in ("max_file_size", "max_archive_size", "max_archive_depth", "decode", "archives",
                    "external_tools"):
            if key not in self.config_keys or key in self.cli_keys:
                continue
            value, default = getattr(self, key), getattr(defaults, key)
            narrower = (default and not value) if isinstance(default, bool) else value < default
            if narrower:
                setattr(self, key, default)
                ignored.append(key.replace("_", "-"))
        return ignored

    @property
    def base_dir(self) -> Optional[Path]:
        return self.config_path.parent if self.config_path else None


# ---------------------------------------------------------------------------
# Loading

_TOP_KEYS = {
    "exclude", "default_excludes", "max_file_size", "max_archive_size", "max_archive_depth",
    "fail_on", "disable", "severity", "allow", "heuristics", "loose_denylist", "decode",
    "archives", "external_tools", "gitleaks",
}
_HEURISTIC_KEYS = {
    "numeric_id_min_length", "allowed_email_domains", "allowed_emails", "allowed_numbers",
    "allowed_hosts", "allowed_ips", "allowed_home_users", "git_identity_domains",
    "git_identity_emails", "entropy_threshold", "entropy_min_length", "internal_patterns",
}
_ALLOW_KEYS = {"rules", "paths", "line", "values", "reason"}


def _names_denylist(pattern: str) -> bool:
    """True when a rule pattern explicitly targets the denylist.

    Wildcards such as ``*`` are fine: they only ever apply to built-in rules,
    because nothing in the public config can touch denylist matches.
    """
    return pattern.strip().lower().startswith("denylist")


def _names_protected(pattern: str) -> bool:
    """True when a rule pattern explicitly targets the denylist or a coverage rule."""
    return pattern.strip().lower().startswith(_PROTECTED_PREFIXES)


def _protected_error(what: str) -> ConfigError:
    return ConfigError(
        f"{what}: coverage rules (scan.*, config.*, git.shallow-clone) can only be changed on the command "
        "line (--disable or --allow), because they report what the scan could not check"
    )


def _norm(d: Dict[str, Any]) -> Dict[str, Any]:
    return {str(k).replace("-", "_"): v for k, v in d.items()}


def _str_list(value: Any, key: str) -> List[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' must be a list of strings")
    return list(value)


def _bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"'{key}' must be true or false")
    return value


def _int(value: Any, key: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ConfigError(f"'{key}' must be an integer >= {minimum}")
    return value


def _compile(pattern: str, key: str) -> Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"'{key}': invalid regular expression ({exc.msg})") from None


def apply_mapping(settings: Settings, data: Dict[str, Any]) -> Settings:
    data = _norm(data)
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")
    settings.config_keys.update(data)
    if "exclude" in data:
        settings.exclude.extend(_str_list(data["exclude"], "exclude"))
    if "default_excludes" in data:
        settings.default_excludes = _bool(data["default_excludes"], "default-excludes")
    for key in ("max_file_size", "max_archive_size"):
        if key in data:
            try:
                setattr(settings, key, parse_size(data[key]))
            except ValueError as exc:
                raise ConfigError(f"'{key.replace('_', '-')}': {exc}") from None
    if "max_archive_depth" in data:
        settings.max_archive_depth = _int(data["max_archive_depth"], "max-archive-depth")
    if "fail_on" in data:
        if data["fail_on"] == "never":
            raise ConfigError("'fail-on = \"never\"' is accepted only on the command line (--fail-on never)")
        if data["fail_on"] not in _FAIL_ON:
            raise ConfigError(f"'fail-on' must be one of {', '.join(_FAIL_ON[:-1])}")
        settings.fail_on = data["fail_on"]
    if "disable" in data:
        disabled = _str_list(data["disable"], "disable")
        if any(_names_denylist(d) for d in disabled):
            raise ConfigError("the denylist cannot be disabled from the public config")
        if any(_names_protected(d) for d in disabled):
            raise _protected_error("'disable'")
        settings.disable.extend(disabled)
    if "severity" in data:
        sev = data["severity"]
        if not isinstance(sev, dict):
            raise ConfigError("'severity' must be a table of rule-id = level")
        for rule, level in sev.items():
            if level not in _SEVERITY_NAMES:
                raise ConfigError(f"'severity': level for '{rule}' must be error, warning or note")
            if _names_denylist(str(rule)):
                raise ConfigError("the denylist severity cannot be changed from the public config")
            if _names_protected(str(rule)):
                raise _protected_error("'severity'")
            settings.severity[str(rule)] = level
    if "allow" in data:
        items = data["allow"]
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            raise ConfigError("'allow' must be a list of tables")
        for i, item in enumerate(items, 1):
            settings.allow.append(_allow_rule(item, i))
    for key in ("loose_denylist", "decode", "archives", "external_tools"):
        if key in data:
            setattr(settings, key, _bool(data[key], key.replace("_", "-")))
    if "gitleaks" in data:
        if data["gitleaks"] not in _GITLEAKS:
            raise ConfigError(f"'gitleaks' must be one of {', '.join(_GITLEAKS)}")
        settings.gitleaks = data["gitleaks"]
    if "heuristics" in data:
        _apply_heuristics(settings, data["heuristics"])
    return settings


def _allow_rule(item: Any, index: int) -> AllowRule:
    where = f"allow #{index}"
    if not isinstance(item, dict):
        raise ConfigError(f"{where}: must be a table")
    item = _norm(item)
    unknown = set(item) - _ALLOW_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")
    rules = _str_list(item.get("rules", []), f"{where}.rules")
    if any(_names_denylist(r) for r in rules):
        raise ConfigError(
            f"{where}: denylist matches can only be allowed inside the private denylist "
            "(use an indented 'allow:' line under the entry)"
        )
    if any(_names_protected(r) for r in rules):
        raise _protected_error(where)
    paths = _str_list(item.get("paths", []), f"{where}.paths")
    try:
        globs = GlobSet(paths) if paths else None
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None
    line = item.get("line")
    if line is not None and not isinstance(line, str):
        raise ConfigError(f"{where}: 'line' must be a string")
    values = {v.lower() for v in _str_list(item.get("values", []), f"{where}.values")}
    reason = item.get("reason", "")
    if not isinstance(reason, str):
        raise ConfigError(f"{where}: 'reason' must be a string")
    if not (rules or globs or line or values):
        raise ConfigError(f"{where}: give at least one of rules, paths, line or values")
    if not rules:
        rules = ["*"]
    return AllowRule(rules=rules, paths=globs, line=_compile(line, f"{where}.line") if line else None,
                     values=values, reason=reason)


def _apply_heuristics(settings: Settings, data: Any) -> None:
    if not isinstance(data, dict):
        raise ConfigError("'heuristics' must be a table")
    data = _norm(data)
    unknown = set(data) - _HEURISTIC_KEYS
    if unknown:
        raise ConfigError(f"unknown heuristics key(s): {', '.join(sorted(unknown))}")
    if "numeric_id_min_length" in data:
        settings.numeric_id_min_length = _int(data["numeric_id_min_length"], "numeric-id-min-length", 6)
    for key in ("allowed_email_domains", "allowed_emails", "allowed_numbers", "allowed_hosts",
                "allowed_ips", "allowed_home_users", "git_identity_domains", "git_identity_emails"):
        if key in data:
            getattr(settings, key).extend(_str_list(data[key], key.replace("_", "-")))
    if "entropy_threshold" in data:
        value = data["entropy_threshold"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 8:
            raise ConfigError("'entropy-threshold' must be a number between 0 and 8")
        settings.entropy_threshold = float(value)
    if "entropy_min_length" in data:
        settings.entropy_min_length = _int(data["entropy_min_length"], "entropy-min-length", 8)
    if "internal_patterns" in data:
        items = data["internal_patterns"]
        if not isinstance(items, list):
            raise ConfigError("'internal-patterns' must be a list")
        for i, item in enumerate(items, 1):
            if isinstance(item, str):
                pattern, label = item, f"internal pattern {i}"
            elif isinstance(item, dict) and isinstance(item.get("pattern"), str):
                pattern = item["pattern"]
                label = str(item.get("label") or f"internal pattern {i}")
            else:
                raise ConfigError("'internal-patterns' items must be strings or {pattern, label} tables")
            rx = _compile(pattern, f"internal-patterns #{i}")
            if rx.search("") is not None:
                raise ConfigError(f"internal-patterns #{i}: pattern matches the empty string")
            settings.internal_patterns.append(InternalPattern(label=label, regex=rx))


def _read_config(path: Path) -> Dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path.name}: {exc.strerror}") from None
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path.name}: invalid JSON (line {exc.lineno})") from None
    else:
        try:
            data = tomlcompat.loads(text)
        except tomlcompat.TomlUnavailable as exc:
            raise ConfigError(f"{path.name}: {exc}") from None
        except ValueError as exc:
            raise ConfigError(f"{path.name}: invalid TOML ({exc})") from None
        if path.name == "pyproject.toml":
            data = data.get("tool", {}).get("prepublish-audit", {})
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name}: expected a table/object")
    return data


def _pyproject_has_section(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return False
    return re.search(r"^\s*\[\s*tool\s*\.\s*[\"']?prepublish-audit", text, re.MULTILINE) is not None


def discover(start: Path) -> Optional[Path]:
    """Find the config file for a scan that starts at *start*."""
    current = start if start.is_dir() else start.parent
    current = current.resolve()
    while True:
        for name in CONFIG_NAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        pyproject = current / "pyproject.toml"
        if pyproject.is_file() and _pyproject_has_section(pyproject):
            return pyproject
        if (current / ".git").exists() or current.parent == current:
            return None
        current = current.parent


def load_settings(config: Optional[Path], *, discover_from: Optional[Path] = None,
                  use_config: bool = True) -> Settings:
    settings = Settings()
    path: Optional[Path] = None
    if config is not None:
        path = config
    elif use_config and discover_from is not None:
        path = discover(discover_from)
    if path is not None:
        apply_mapping(settings, _read_config(path))
        settings.config_path = path.resolve()
    return settings


def parse_cli_allow(values: Sequence[str]) -> List[Tuple[str, str]]:
    """``--allow RULE:GLOB`` pairs from the command line (coverage rules allowed, the denylist not)."""
    pairs = []
    for raw in values:
        rule, sep, glob = raw.partition(":")
        if not sep or not rule or not glob:
            raise ConfigError("--allow expects RULE:PATH-GLOB, for example leak.email:docs/**")
        if _names_denylist(rule):
            raise ConfigError("--allow cannot allow denylist matches")
        pairs.append((rule, glob))
    return pairs
