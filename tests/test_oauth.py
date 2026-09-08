"""
Тести чистих частин OAuth-помічника: сам обмін інтерактивний, але побудова
запиту й PKCE — ні, а помилка саме в них тиха й небезпечна.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "scripts"))

import google_oauth as oauth                                      # noqa: E402


class TestPKCE(unittest.TestCase):
    def test_challenge_is_s256_of_verifier(self):
        verifier, challenge = oauth.pkce_pair()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        self.assertEqual(challenge, expected)

    def test_verifier_is_fresh_each_time(self):
        self.assertNotEqual(oauth.pkce_pair()[0], oauth.pkce_pair()[0])

    def test_verifier_length_within_rfc(self):
        verifier, _ = oauth.pkce_pair()
        self.assertTrue(43 <= len(verifier) <= 128)


class TestAuthUrl(unittest.TestCase):
    def params(self, **kwargs):
        url = oauth.build_auth_url("cid", "http://127.0.0.1:1234/",
                                   scope=kwargs.get("scope", oauth.NARROW_SCOPE),
                                   challenge="chal", state="st")
        return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))

    def test_offline_and_consent_required_for_refresh_token(self):
        """Без access_type=offline і prompt=consent refresh token не приїде."""
        params = self.params()
        self.assertEqual(params["access_type"], "offline")
        self.assertEqual(params["prompt"], "consent")

    def test_pkce_method_is_s256(self):
        self.assertEqual(self.params()["code_challenge_method"], "S256")

    def test_default_scope_is_the_narrow_one(self):
        """Вузький доступ не дає дотягнутися до особистого календаря."""
        self.assertEqual(self.params()["scope"], oauth.NARROW_SCOPE)
        self.assertIn("app.created", oauth.NARROW_SCOPE)

    def test_redirect_is_loopback(self):
        self.assertTrue(self.params()["redirect_uri"].startswith("http://127.0.0.1:"))


class TestPortPicking(unittest.TestCase):
    def test_free_port_is_usable(self):
        port = oauth.free_port()
        self.assertTrue(1024 < port < 65536)


if __name__ == "__main__":
    unittest.main(verbosity=2)
