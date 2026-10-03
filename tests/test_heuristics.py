import unittest

from prepublish_audit.config import InternalPattern, Settings
from prepublish_audit.denylist import Denylist
from prepublish_audit.engine import Engine
from prepublish_audit.util import luhn_ok

import re


def scan(text: str, path: str = "notes.txt", settings: Settings = None, target: str = "text"):
    eng = Engine(settings or Settings(), Denylist())
    return eng.scan_text(text, target=target, match_path=path, display=path, origin="file")


def ids(text: str, path: str = "notes.txt", settings: Settings = None):
    return [f.rule_id for f in scan(text, path, settings)]


def make_card(prefix: str, length: int = 16) -> str:
    body = prefix
    digit = 7
    while len(body) < length - 1:
        body += str(digit)
        digit = (digit * 3 + 1) % 10
    for check in "0123456789":
        if luhn_ok(body + check):
            return body + check
    raise AssertionError("unreachable")


class HomePathTests(unittest.TestCase):
    def test_flagged(self):
        for text in ("log at /Users/alice/projects/app/build.log", "cd /home/bob/src/app",
                     r"C:\Users\Carol\Documents\plan.docx", r'"C:\\Users\\carol\\AppData\\x"',
                     "/mnt/c/Users/dave/code", "file:///Users/erin/Desktop/a.png"):
            with self.subTest(text):
                self.assertIn("leak.home-path", ids(text))

    def test_ignored(self):
        for text in ("/Users/runner/work/repo", "/home/ubuntu/app", "/home/bob", "/Users/$USER/x",
                     "/Users/<name>/x", "https://example.com/home/news/today", "~/projects/x",
                     "/home/linuxbrew/.linuxbrew/bin"):
            with self.subTest(text):
                self.assertNotIn("leak.home-path", ids(text))

    def test_allowed_users_are_configurable(self):
        s = Settings()
        s.allowed_home_users.append("buildbot")
        self.assertNotIn("leak.home-path", ids("/home/buildbot/x/y", settings=s))


class VolumeTests(unittest.TestCase):
    def test_volumes(self):
        self.assertIn("leak.mounted-volume", ids("rsync /Volumes/Backup2/photos ."))
        self.assertNotIn("leak.mounted-volume", ids("/Volumes/Macintosh HD/Library"))


class EmailTests(unittest.TestCase):
    def test_emails(self):
        self.assertIn("leak.email", ids("contact alice.smith@acme-corp.io"))
        for text in ("bob@example.com", "icon@2x.png", "git@github.com:org/repo.git", "noreply@acme-corp.io",
                     "you@yourcompany.com", "123+bot@users.noreply.github.com"):
            with self.subTest(text):
                self.assertNotIn("leak.email", ids(text))

    def test_allowed_domains_and_lockfiles(self):
        s = Settings()
        s.allowed_email_domains.append("acme-corp.io")
        self.assertNotIn("leak.email", ids("security@acme-corp.io", settings=s))
        self.assertNotIn("leak.email", ids("security@sub.acme-corp.io", settings=s))
        self.assertNotIn("leak.email", ids('"author": "x <maint@vendor.dev>"', path="web/package-lock.json"))


class NumericIdTests(unittest.TestCase):
    def test_flagged(self):
        for text in ("customer 7302958164", "CAMPAIGN=73029581640273", "id7302958164", "act 730295816402736x"):
            with self.subTest(text):
                self.assertIn("leak.numeric-id", ids(text))

    def test_ignored(self):
        for text in ("x = 4294967295", "pi = 3.14159265358979", "n = 123456789012", "zero = 0000000000",
                     "budget 5000000000", "mask 0x12345678901", "sha a1b2c3d4e5f6a7b8c9d01234567890abcdef12",
                     '"created_at": 1696172345', "placeholder 29862700000000000", "short 730295816"):
            with self.subTest(text):
                self.assertNotIn("leak.numeric-id", ids(text))

    def test_min_length_and_allowlist(self):
        s = Settings()
        s.numeric_id_min_length = 8
        self.assertIn("leak.numeric-id", ids("acct 73029581", settings=s))
        s.allowed_numbers.append("73029581")
        self.assertNotIn("leak.numeric-id", ids("acct 73029581", settings=s))


class NetworkTests(unittest.TestCase):
    def test_ip_addresses(self):
        found = scan("a 10.20.30.40 b 100.101.102.103 c 93.184.215.14 d fd12:3456:789a::1")
        self.assertEqual([f.rule_id for f in found], ["leak.ip-address"] * 4)
        self.assertIn("private", found[0].message)
        self.assertIn("VPN", found[1].message)
        self.assertIn("public", found[2].message)
        for text in ("dns 8.8.8.8", "doc 192.0.2.10", "lo 127.0.0.1", "vpc 10.0.0.0/8", "version v1.2.3.4",
                     "oid 1.3.6.1.4.1", "slice a[1::2]", "doc6 2001:db8::1", "padded 01.02.03.04"):
            with self.subTest(text):
                self.assertNotIn("leak.ip-address", ids(text))

    def test_internal_hosts(self):
        for text in ("ssh deploy@db01.corp", "see https://wiki.internal/page", "Janes-MacBook-Pro.local",
                     "api.prod.eu.internal"):
            with self.subTest(text):
                self.assertIn("leak.internal-host", ids(text))
        self.assertIn("leak.internal-host", ids(r"copy to \\fs01.acme\builds\nightly"))
        self.assertNotIn("leak.internal-host", ids(r"map \\server\share as Z:"))
        for text in ("this.local", "host.docker.internal", "settings.local.json", "db.example.internal",
                     "self.config.local"):
            with self.subTest(text):
                self.assertNotIn("leak.internal-host", ids(text))

    def test_internal_links(self):
        found = scan("notes: https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUv/edit")
        self.assertEqual(found[0].rule_id, "leak.internal-link")
        self.assertIn("Google Docs", found[0].message)
        self.assertIn("leak.internal-link", ids("https://acme.atlassian.net/browse/OPS-12"))
        self.assertNotIn("leak.internal-link", ids("https://docs.google.com/document/d/YOUR_DOC_ID_HERE/edit"))


class MarkerAndPersonalDataTests(unittest.TestCase):
    def test_confidential_markers(self):
        self.assertIn("leak.confidential-marker", ids("CONFIDENTIAL - board deck"))
        self.assertIn("leak.confidential-marker", ids("Do not distribute outside the team."))
        self.assertNotIn("leak.confidential-marker", ids("We keep your data confidential."))

    def test_phone_numbers(self):
        self.assertIn("leak.phone-number", ids("call +44 7700 900123"))
        self.assertNotIn("leak.phone-number", ids("call +1-202-555-0143"))
        self.assertNotIn("leak.phone-number", ids("+1 555 0100"))

    def test_payment_cards(self):
        card = make_card("4539")
        grouped = " ".join(card[i:i + 4] for i in range(0, 16, 4))
        self.assertIn("leak.payment-card", ids(f"card {grouped}"))
        self.assertIn("leak.payment-card", ids(f"card {card}"))
        self.assertNotIn("leak.payment-card", ids("stripe test 4242 4242 4242 4242"))
        bad = card[:-1] + str((int(card[-1]) + 1) % 10)
        self.assertNotIn("leak.payment-card", ids(f"card {bad}"))
        self.assertNotIn("leak.payment-card", ids(f"card {make_card('9123')}"))


class CloudAndAccountTests(unittest.TestCase):
    def test_cloud(self):
        self.assertIn("leak.cloud-account-id", ids("arn:aws:iam::730215948613:role/deploy"))
        self.assertNotIn("leak.cloud-account-id", ids("arn:aws:iam::123456789012:role/deploy"))
        self.assertIn("leak.cloud-resource", ids("aws s3 cp s3://acme-prod-logs/x ."))
        self.assertIn("leak.cloud-resource", ids("https://acme-assets.s3.amazonaws.com/a.png"))
        self.assertIn("leak.cloud-resource", ids("instance i-0a1b2c3d4e5f60718"))
        self.assertNotIn("leak.cloud-resource", ids("s3://my-bucket/path"))
        self.assertNotIn("leak.cloud-resource", ids("instance i-1234567890abcdef0"))

    def test_ad_identifiers(self):
        for text in ("ca-app-pub-7302958164027365~4920571836", "gtag('config', 'AW-730295816')",
                     "act_730295816402", "G-AB12CD34EF"):
            with self.subTest(text):
                self.assertIn("leak.ad-identifier", ids(text))
        self.assertNotIn("leak.ad-identifier", ids("pub-0000000000000000"))

    def test_apple_developer_ids(self):
        for text in ("DEVELOPMENT_TEAM = Q7K2M9X4LP;", "<key>TeamIdentifier</key>\n<array>\n<string>Q7K2M9X4LP</string>",
                     "key: AuthKey_Q7K2M9X4LP.p8", 'issuer_id = "6f1c2a7e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"'):
            with self.subTest(text):
                self.assertIn("leak.apple-developer-id", ids(text, path="App.xcodeproj/project.pbxproj"))
        self.assertNotIn("leak.apple-developer-id", ids("DEVELOPMENT_TEAM = ABCDE12345;"))

    def test_identifier_assignments(self):
        self.assertIn("leak.identifier-assignment", ids("account_id: 48291736"))
        found = ids('customer_id = "7302958164"')
        self.assertIn("leak.identifier-assignment", found)
        self.assertNotIn("leak.numeric-id", found)
        self.assertNotIn("leak.identifier-assignment", ids("user_id = args.user_id"))
        self.assertNotIn("leak.identifier-assignment", ids("grid = 48291736"))

    def test_internal_name_patterns_from_config(self):
        s = Settings()
        s.internal_patterns.append(InternalPattern("project codenames", re.compile(r"(?i)\bproject-[a-z]+\b")))
        found = scan("deploy project-heron today", settings=s)
        self.assertEqual(found[0].rule_id, "leak.internal-name")
        self.assertIn("project codenames", found[0].message)


class CertificateBundleTests(unittest.TestCase):
    def test_public_pem_blocks_and_serials_are_not_secrets(self):
        import random
        import string

        rng = random.Random(3)
        alphabet = string.ascii_letters + string.digits + "+/"
        body = "\n".join("".join(rng.choice(alphabet) for _ in range(64)) for _ in range(20))
        bundle = ("# Issuer: CN=Example Root CA\n# Serial: 73029581640273958164\n"
                  "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n")
        self.assertEqual(ids(bundle, path="certs/cacert.pem"), [])
        # The same random lines outside a certificate are still reported.
        self.assertIn("secret.high-entropy-string", ids(body, path="certs/notes.txt"))


class TargetTests(unittest.TestCase):
    def test_binary_target_skips_noisy_heuristics(self):
        found = scan("call +44 7700 900123 and 7302958164", target="binary")
        self.assertEqual(found, [])

    def test_path_target(self):
        eng = Engine(Settings(), Denylist())
        found = eng.scan_path("exports/report-7302958164.csv", "exports/report-7302958164.csv")
        self.assertEqual([f.rule_id for f in found], ["leak.numeric-id"])
        self.assertEqual(found[0].detail, "file or directory name")


if __name__ == "__main__":
    unittest.main()
