"""End-to-end runtime tests (stdlib unittest)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from aegisflow.config import AppConfig  # noqa: E402
from aegisflow.runtime import Runtime  # noqa: E402


class TestRuntime(unittest.TestCase):
    def _rt(self):
        d = tempfile.mkdtemp()
        os.environ["AEGISFLOW_AUDIT_DIR"] = os.path.join(d, "audit")
        os.environ["AEGISFLOW_MODE"] = "onprem"
        return Runtime(AppConfig.from_env())

    def test_full_flow(self):
        rt = self._rt()
        self.assertEqual(rt.audit.verify(), [])
        for i in range(40):
            rt.ingest_raw({
                "source": "identity", "entity_id": "carol", "entity_type": "user",
                "action": "login", "outcome": "success",
                "features": {"failed_logins_1h": 0.2, "new_geo": 0.0,
                             "impossible_travel_mins": 0.0},
            })
        rt.ingest_raw({
            "source": "identity", "entity_id": "carol", "entity_type": "user",
            "action": "login", "outcome": "failed",
            "features": {"failed_logins_1h": 40.0, "new_geo": 1.0,
                         "impossible_travel_mins": 6.0},
        })
        rt.ingest_raw({
            "source": "edr", "entity_id": "ws-dom", "entity_type": "device",
            "action": "exec", "outcome": "success",
            "features": {"priv_escalation_flag": 1.0, "suspicious_cmdline": 1.0,
                         "lateral_moves_1h": 7.0},
        })
        incidents = rt.drain()
        self.assertGreaterEqual(incidents, 1)
        stats = rt.stats()
        self.assertTrue(stats["audit_chain_integrity"])
        self.assertGreaterEqual(stats["bus"]["produced"], 41)

        subj = {"identity": "e2e-lead", "role": "soc_lead"}
        from aegisflow.detection.intelligence import Reasoning
        for inc in rt.incidents[:1]:
            reasoning = Reasoning(
                summary=inc["explanation"]["narrative"],
                recommended_actions=inc["reasoning"]["recommended_actions"],
                confidence=inc["reasoning"]["confidence"],
                rationale=inc["reasoning"]["rationale"],
            )
            for a in rt.response.plan(inc["entity_id"], reasoning,
                                      inc["final_score"]):
                rt.response.execute(a, subj)
        self.assertEqual(rt.audit.verify(), [])
        self.assertGreater(rt.audit.length, 0)

    def test_mode_describe(self):
        rt = self._rt()
        desc = rt.cfg.describe()
        self.assertEqual(desc["deployment_mode"], "onprem")
        self.assertEqual(desc["response_mode"], "approve")


if __name__ == "__main__":
    unittest.main()
