"""Shared test helpers.

Secret-shaped test values are assembled at runtime from fragments, so that
no secret scanner (ours or gitleaks) ever sees a complete credential in the
source of this repository. They are random and belong to no real account.
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional
from unittest import mock

from prepublish_audit.cli import main

ALNUM = string.ascii_letters + string.digits
UPPER_DIGITS = string.ascii_uppercase + string.digits
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def rand(alphabet: str, n: int, seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class Fake:
    """Credential-shaped values for tests (built at runtime, never real)."""

    @staticmethod
    def github() -> str:
        return "gh" + "p_" + rand(ALNUM, 36, 1)

    @staticmethod
    def aws_key_id() -> str:
        return "AK" + "IA" + rand(B32, 16, 2)

    @staticmethod
    def aws_secret() -> str:
        return rand(ALNUM + "/+", 40, 3)

    @staticmethod
    def google_api_key() -> str:
        return "AI" + "za" + rand(ALNUM + "_-", 35, 4)

    @staticmethod
    def google_oauth() -> str:
        return "ya" + "29." + rand(ALNUM + "_-", 60, 5)

    @staticmethod
    def google_client_secret() -> str:
        return "GOC" + "SPX-" + rand(ALNUM + "_-", 28, 6)

    @staticmethod
    def gitlab() -> str:
        return "gl" + "pat-" + rand(ALNUM, 20, 7)

    @staticmethod
    def slack() -> str:
        return "xo" + "xb-" + rand(string.digits, 12, 8) + "-" + rand(string.digits, 13, 9) + "-" + rand(ALNUM, 24, 10)

    @staticmethod
    def slack_webhook() -> str:
        return ("https://hooks.slack" + ".com/services/T" + rand(UPPER_DIGITS, 10, 11) + "/B"
                + rand(UPPER_DIGITS, 10, 12) + "/" + rand(ALNUM, 24, 13))

    @staticmethod
    def stripe_live() -> str:
        return "sk" + "_live_" + rand(ALNUM, 24, 14)

    @staticmethod
    def stripe_test() -> str:
        return "sk" + "_test_" + rand(ALNUM, 24, 15)

    @staticmethod
    def stripe_webhook() -> str:
        return "wh" + "sec_" + rand(ALNUM, 32, 16)

    @staticmethod
    def npm() -> str:
        return "np" + "m_" + rand(ALNUM, 36, 17)

    @staticmethod
    def pypi() -> str:
        return "py" + "pi-AgEIcHlwaS5vcmc" + rand(ALNUM + "_-", 60, 18)

    @staticmethod
    def openai() -> str:
        return "sk" + "-proj-" + rand(ALNUM, 24, 19) + "T3Blbk" + "FJ" + rand(ALNUM, 24, 20)

    @staticmethod
    def anthropic() -> str:
        return "sk" + "-ant-api03-" + rand(ALNUM + "_-", 93, 21)

    @staticmethod
    def meta() -> str:
        return "EA" + "AB" + rand(ALNUM, 150, 22)

    @staticmethod
    def meta_app() -> str:
        return rand("123456789", 15, 23) + "|" + rand(ALNUM + "_-", 27, 24)

    @staticmethod
    def jwt(payload: Optional[dict] = None) -> str:
        header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        body = b64url(json.dumps(payload or {"sub": "svc-42", "role": "deploy"}).encode())
        return f"{header}.{body}." + rand(ALNUM + "_-", 43, 25)

    @staticmethod
    def private_key() -> str:
        body = "\n".join(rand(ALNUM + "+/", 64, 26 + i) for i in range(6))
        return "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----\n"

    @staticmethod
    def high_entropy() -> str:
        return rand(ALNUM, 40, 40)


class Result(NamedTuple):
    code: int
    out: str
    err: str


def run_cli(*args: str, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> Result:
    out, err = io.StringIO(), io.StringIO()
    old = os.getcwd()
    try:
        if cwd is not None:
            os.chdir(cwd)
        with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
    finally:
        os.chdir(old)
    return Result(code, out.getvalue(), err.getvalue())


def scan_json(root: Path, *args: str, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> dict:
    res = run_cli("scan", "--format", "json", "--gitleaks", "never", "--no-external-tools", *args, str(root),
                  cwd=cwd if cwd is not None else root, env=env)
    if res.code == 2:
        raise AssertionError(f"scan failed: {res.err}")
    data = json.loads(res.out)
    data["_exit"] = res.code
    return data


def rules_of(report: dict) -> List[str]:
    return [f["rule_id"] for f in report["findings"]]


def findings_for(report: dict, rule_id: str) -> List[dict]:
    return [f for f in report["findings"] if f["rule_id"] == rule_id]


_CI_VARS = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION",
            "CODEBUILD_BUILD_ID", "DRONE", "BITBUCKET_BUILD_NUMBER", "CIRCLECI", "TRAVIS",
            "PREPUBLISH_AUDIT_DENYLIST", "PREPUBLISH_AUDIT_ALLOW_REVEAL", "NO_COLOR")


class TempTestCase(unittest.TestCase):
    """A temporary directory plus an environment isolated from the developer's machine."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pa-test-")).resolve()
        self.home = self.tmp / "_home"
        self.home.mkdir()
        env = {k: v for k, v in os.environ.items() if k not in _CI_VARS}
        env.update({
            "HOME": str(self.home),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Test Author",
            "GIT_AUTHOR_EMAIL": "12345+tester@users.noreply.github.com",
            "GIT_COMMITTER_NAME": "Test Author",
            "GIT_COMMITTER_EMAIL": "12345+tester@users.noreply.github.com",
        })
        patcher = mock.patch.dict(os.environ, env, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel: str, content, mode: Optional[int] = None) -> Path:
        path = self.tmp / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        if mode is not None:
            path.chmod(mode)
        return path

    def denylist(self, text: str, name: str = "deny.txt") -> Path:
        folder = self.tmp / "_private"
        folder.mkdir(exist_ok=True)
        path = folder / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def tree(self, name: str = "tree") -> Path:
        root = self.tmp / name
        root.mkdir(exist_ok=True)
        return root


def git(cwd: Path, *args: str, env: Optional[Dict[str, str]] = None) -> str:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    p = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", "-c", "init.defaultBranch=main",
                        *args], cwd=cwd, env=full_env, capture_output=True, text=True)
    if p.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {p.stderr}")
    return p.stdout


def init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q")
    return path


def commit_all(repo: Path, message: str, *, name: Optional[str] = None, email: Optional[str] = None) -> str:
    env = {}
    if name:
        env.update(GIT_AUTHOR_NAME=name, GIT_COMMITTER_NAME=name)
    if email:
        env.update(GIT_AUTHOR_EMAIL=email, GIT_COMMITTER_EMAIL=email)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--allow-empty", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD").strip()


def has_git() -> bool:
    return shutil.which("git") is not None


POSIX = os.name == "posix"
PY = sys.executable
