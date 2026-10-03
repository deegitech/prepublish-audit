import base64
import unittest

from prepublish_audit.config import Settings
from prepublish_audit.denylist import Denylist
from prepublish_audit.engine import Engine

from .helpers import ALNUM, Fake, rand


def scan(text: str, path: str = "src/app.py", settings: Settings = None):
    eng = Engine(settings or Settings(), Denylist())
    return eng.scan_text(text, target="text", match_path=path, display=path, origin="file")


def ids(text: str, path: str = "src/app.py", settings: Settings = None):
    return [f.rule_id for f in scan(text, path, settings)]


class SecretRuleTests(unittest.TestCase):
    def assertFinds(self, rule_id: str, text: str, path: str = "src/app.py"):
        found = ids(text, path)
        self.assertIn(rule_id, found, f"{rule_id} not found in {text[:60]!r}; got {found}")

    def assertClean(self, text: str, path: str = "src/app.py"):
        found = scan(text, path)
        self.assertEqual([f.rule_id for f in found], [], f"unexpected findings in {text[:80]!r}")

    def test_vendor_tokens(self):
        cases = {
            "secret.github-token": f'token = "{Fake.github()}"',
            "secret.aws-access-key-id": f"key: {Fake.aws_key_id()}",
            "secret.google-api-key": f"maps = '{Fake.google_api_key()}'",
            "secret.google-oauth-token": f"Bearer value {Fake.google_oauth()}",
            "secret.google-oauth-client-secret": f"client: {Fake.google_client_secret()}",
            "secret.gitlab-token": f"GITLAB={Fake.gitlab()}",
            "secret.slack-token": f"slack {Fake.slack()}",
            "secret.slack-webhook": f"url = {Fake.slack_webhook()}",
            "secret.stripe-live-key": f"stripe {Fake.stripe_live()}",
            "secret.stripe-test-key": f"stripe {Fake.stripe_test()}",
            "secret.stripe-webhook-secret": f"hook {Fake.stripe_webhook()}",
            "secret.npm-token": f"//registry.npmjs.org/:_authToken={Fake.npm()}",
            "secret.pypi-token": f"password = {Fake.pypi()}",
            "secret.openai-api-key": f"OPENAI={Fake.openai()}",
            "secret.anthropic-api-key": f"key={Fake.anthropic()}",
            "secret.meta-access-token": f"access_token={Fake.meta()}&x=1",
            "secret.meta-app-token": f"app_token = {Fake.meta_app()}",
            "secret.jwt": f"auth: {Fake.jwt()}",
            "secret.private-key": Fake.private_key(),
        }
        for rule_id, text in cases.items():
            with self.subTest(rule_id):
                self.assertFinds(rule_id, text)

    def test_aws_secret_key_assignment(self):
        self.assertFinds("secret.aws-secret-access-key", f'aws_secret_access_key = "{Fake.aws_secret()}"')

    def test_aws_documentation_key_is_ignored(self):
        self.assertClean("key = " + "AK" + "IA" + "IOSFODNN7" + "EXAMPLE")

    def test_repeated_character_placeholders_are_ignored(self):
        self.assertClean('token = "' + "gh" + "p_" + "x" * 36 + '"')
        self.assertClean('stripe = "' + "sk" + "_live_" + "0" * 24 + '"')

    def test_private_key_header_without_body_is_ignored(self):
        self.assertClean("Keys start with -----BEGIN " + "PRIVATE KEY----- and end with a footer.")

    def test_jwt_sample_and_non_jwt_are_ignored(self):
        sample = Fake.jwt({"sub": "1234567890", "name": "John Doe", "iat": 1516239022})
        self.assertNotIn("secret.jwt", ids(f"example {sample}"))
        broken = "eyJ" + rand(ALNUM, 20, 1) + ".eyJ" + rand(ALNUM, 20, 2) + "." + rand(ALNUM, 10, 3)
        self.assertNotIn("secret.jwt", ids(f"x {broken}"))

    def test_credentials_in_url(self):
        self.assertFinds("secret.credentials-in-url", "DB=postgres://app:" + "Zq8" + "vL2pT9wK" + "@db.example.com/x")
        self.assertClean("postgres://user:password@localhost:5432/db")
        self.assertClean("postgres://user:${DB_PASSWORD}@localhost/db")

    def test_authorization_header(self):
        basic = base64.b64encode(b"deploy:" + b"Kp4" + b"mZ9wQ2x").decode()
        self.assertFinds("secret.authorization-header", f"Authorization: Basic {basic}")
        placeholder = base64.b64encode(b"user:password").decode()
        self.assertNotIn("secret.authorization-header", ids(f"Authorization: Basic {placeholder}"))

    def test_generic_assignment(self):
        self.assertIn("secret.generic-assignment", ids('db_password = "' + "Tr0ub4" + "dor-9xK2" + '"'))
        self.assertNotIn("secret.generic-assignment", ids('password = "changeme"'))
        self.assertNotIn("secret.generic-assignment", ids('token_type = "bearer_token"'))
        self.assertNotIn("secret.generic-assignment", ids('api_key = "' + "test-key-" + "12345678" + '"'))
        self.assertNotIn("secret.generic-assignment", ids('secret_env = "GITHUB_TOKEN"'))
        self.assertNotIn("secret.generic-assignment", ids('token_url = "https://oauth2.example.com/token"'))

    def test_high_entropy_strings(self):
        token = Fake.high_entropy()
        self.assertIn("secret.high-entropy-string", ids(f"value = '{token}'"))
        self.assertClean("IDEDidComputeMac32BitWarning and APP_CLIP7-TEASER_EN_1080x1920")
        self.assertClean("commit " + "deadbeef" * 5)
        self.assertNotIn("secret.high-entropy-string", ids(f'"integrity": "sha512-{token}"'))
        self.assertNotIn("secret.high-entropy-string", ids(f'"{token}"', path="package-lock.json"))

    def test_entropy_threshold_is_configurable(self):
        s = Settings()
        s.entropy_threshold = 7.9
        self.assertNotIn("secret.high-entropy-string", ids(f"v = '{Fake.high_entropy()}'", settings=s))

    def test_disabled_rule(self):
        s = Settings()
        s.disable.append("secret.*")
        self.assertEqual(ids(f'token = "{Fake.github()}"', settings=s), [])

    def test_severity_override(self):
        s = Settings()
        s.severity["secret.github-token"] = "note"
        found = scan(f'token = "{Fake.github()}"', settings=s)
        self.assertEqual(found[0].severity, "note")

    def test_inline_pragma_suppresses_builtin_rules(self):
        text = f'token = "{Fake.github()}"  # prepublish-audit:allow secret.github-token'
        self.assertEqual(ids(text), [])
        text = f'token = "{Fake.github()}"  # prepublish-audit:allow leak.email'
        self.assertEqual(ids(text), ["secret.github-token"])

    def test_secret_inside_base64(self):
        inner = f'{{"token": "{Fake.github()}"}}'.encode()
        found = scan(f"blob = '{base64.b64encode(inner).decode()}'")
        self.assertIn("secret.github-token", [f.rule_id for f in found])
        self.assertTrue(any("base64" in (f.detail or "") for f in found))

    def test_jwt_payload_is_decoded(self):
        token = Fake.jwt({"email": "dana@acme-corp.io", "sub": "u-77"})
        found = ids(f"t = {token}")
        self.assertIn("secret.jwt", found)
        self.assertIn("leak.email", found)

    def test_findings_carry_columns_and_lengths(self):
        token = Fake.github()
        found = scan(f'x = 1\ntoken = "{token}"\n')
        f = found[0]
        self.assertEqual((f.line, f.column), (2, 10))
        self.assertEqual(f.match_length, len(token))
        self.assertEqual(f.end_column, 10 + len(token))

    def test_repr_never_contains_the_secret(self):
        token = Fake.github()
        f = scan(f'token = "{token}"')[0]
        self.assertNotIn(token, repr(f))
        self.assertNotIn(token, f.redacted())


if __name__ == "__main__":
    unittest.main()
