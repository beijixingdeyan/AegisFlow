"""Security tests: crypto/KMS, mTLS/token, audit hash-chain, RBAC+ABAC."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from aegisflow.config import KMSConfig, KMSProvider  # noqa: E402
from aegisflow.security.crypto import CryptoBox, CryptoError  # noqa: E402
from aegisflow.security.audit import AuditChain  # noqa: E402
from aegisflow.security.access import AccessDenied, PolicyEngine  # noqa: E402
from aegisflow.security.mtls import (  # noqa: E402
    Identity, TokenManager, MutualAuthChannel, MTLSHandshakeError,
)


class TestCrypto(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        box = CryptoBox(KMSConfig(provider=KMSProvider.LOCAL), passphrase="test")
        env = box.encrypt(b"secret payload", aad=b"ctx")
        self.assertEqual(box.decrypt(env, aad=b"ctx"), b"secret payload")
        tampered = env[:8] + bytes([env[8] ^ 0xFF]) + env[9:]
        with self.assertRaises(CryptoError):
            box.decrypt(tampered, aad=b"ctx")


class TestAuditChain(unittest.TestCase):
    def _chain(self):
        d = tempfile.mkdtemp()
        return AuditChain(d)

    def test_integrity_and_tamper(self):
        chain = self._chain()
        for i in range(10):
            chain.record("admin", "policy:update", "rule:r1", "success", {"v": i})
        self.assertEqual(chain.length, 10)
        self.assertEqual(chain.verify(), [])
        chain._chain[5].digest = "0" * 64
        self.assertNotEqual(chain.verify(), [])

    def test_head_linking(self):
        chain = self._chain()
        chain.record("a", "x", "t")
        first = chain.head_digest
        chain.record("b", "y", "t")
        self.assertEqual(chain._chain[-1].prev_digest, first)


class TestMTLS(unittest.TestCase):
    def test_token_refresh(self):
        tm = TokenManager(ttl_s=60)
        tm.register_peer("node-a", b"sekret-a")
        tok = tm.issue("node-a")
        self.assertEqual(tm.validate(tok), "node-a")
        new_tok = tm.refresh("node-a", tok)
        with self.assertRaises(MTLSHandshakeError):
            tm.validate(tok)   # 旧令牌已吊销
        self.assertEqual(tm.validate(new_tok), "node-a")

    def test_mutual_auth_handshake(self):
        tm = TokenManager()
        a = MutualAuthChannel(Identity("node-a"), tm)
        b = MutualAuthChannel(Identity("node-b"), tm)
        secret = b"shared"
        a.bind_peer_secret("node-b", secret)
        b.bind_peer_secret("node-a", secret)
        challenge = b"challenge-bytes"
        resp = a.handshake_as_peer("node-b", challenge)
        self.assertTrue(a.verify_peer("node-b", challenge, resp))
        tm.register_peer("node-a", secret)
        tok = a.establish("node-b")
        self.assertEqual(tm.validate(tok), "node-a")

    def test_mutual_auth_wrong_secret_fails(self):
        tm = TokenManager()
        a = MutualAuthChannel(Identity("a"), tm)
        b = MutualAuthChannel(Identity("b"), tm)
        a.bind_peer_secret("b", b"right")
        b.bind_peer_secret("a", b"wrong")   # b 与 a 对同一密钥的认知不一致
        challenge = b"c"
        # b 用自己的(错误)密钥应答，a 用自己持有的密钥校验 -> 应失败
        resp = b.handshake_as_peer("a", challenge)
        self.assertFalse(a.verify_peer("b", challenge, resp))


class TestAccessControl(unittest.TestCase):
    def setUp(self):
        self.pe = PolicyEngine()

    def test_rbac_denied(self):
        viewer = {"identity": "v", "role": "viewer"}
        self.pe.check(viewer, "read", "event")
        with self.assertRaises(AccessDenied):
            self.pe.check(viewer, "write", "incident")
        with self.assertRaises(AccessDenied):
            self.pe.check(viewer, "execute", "response")

    def test_abac_high_severity(self):
        analyst = {"identity": "a", "role": "analyst"}
        self.pe.check(analyst, "write", "incident", {"severity": "low"})
        with self.assertRaises(AccessDenied):
            self.pe.check(analyst, "write", "incident", {"severity": "critical"})
        lead = {"identity": "l", "role": "soc_lead"}
        self.pe.check(lead, "execute", "response")

    def test_field_level_redaction(self):
        data = {"entity": "e", "command": "whoami", "sso_email": "x@y.com"}
        for_analyst = self.pe.filter_fields("analyst", "event", data)
        self.assertNotEqual(for_analyst["command"], "[redacted]")
        self.assertEqual(for_analyst["sso_email"], "[redacted]")
        for_admin = self.pe.filter_fields("admin", "event", data)
        self.assertEqual(for_admin["sso_email"], "x@y.com")

    def test_policy_snapshot_auditable(self):
        snap = self.pe.policy_snapshot()
        self.assertIn("admin", snap["roles"])
        self.assertTrue(any(ap["name"] == "high-severity-incident-requires-soc-lead"
                            for ap in snap["attribute_policies"]))


if __name__ == "__main__":
    unittest.main()
