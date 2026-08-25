"""Detection pipeline tests (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from aegisflow.detection.baseline import BaselineProfiler, FeatureStat  # noqa: E402
from aegisflow.detection.anomaly import AnomalyScorer  # noqa: E402
from aegisflow.detection.explain import Explainer  # noqa: E402
from aegisflow.detection.intelligence import MockIntelligence  # noqa: E402
from aegisflow.detection.pipeline import DetectionPipeline  # noqa: E402
from aegisflow.dataplane.ingestion import Event  # noqa: E402


def _login_event(entity, features, outcome="success"):
    return Event(event_id="e", ts=0.0, source="identity", entity_id=entity,
                 entity_type="user", action="login", outcome=outcome, features=features)


class TestBaseline(unittest.TestCase):
    def test_feature_stat_online_std(self):
        st = FeatureStat(name="x")
        for v in [10, 10, 10, 10]:
            st.update(v, 1.0)
        self.assertEqual(st.std, 0)
        self.assertIsNone(st.zscore(10))  # 方差为 0 -> 未训练

    def test_baseline_profiler_learns(self):
        profiler = BaselineProfiler(min_samples=3)
        # 用带方差的训练数据（恒定值 -> 方差为0，zscore 无意义）
        for i in range(20):
            profiler.observe("alice", "user", {"x": 5.0 + (i % 4) * 0.1, "y": 2.0}, ts=float(i))
        self.assertTrue(profiler.learned("alice"))
        prof = profiler.profile("alice")
        zs = prof.zscore_features({"x": 5.05, "y": 2.0})
        self.assertIsNotNone(zs["x"])
        self.assertLess(abs(zs["x"]), 1.5)
        zs2 = prof.zscore_features({"x": 500.0, "y": 2.0})
        self.assertGreater(abs(zs2["x"]), 10)


class TestAnomaly(unittest.TestCase):
    def test_detects_abnormal_after_baseline(self):
        profiler = BaselineProfiler(min_samples=3)
        scorer = AnomalyScorer()
        for i in range(30):
            profiler.observe("alice", "user",
                             {"login_rate": 1.0 + (i % 3) * 0.1, "geo": 2.0}, ts=1.0)
        prof = profiler.profile("alice")
        normal = scorer.evaluate(prof, {"login_rate": 1.05, "geo": 2.0})
        self.assertFalse(normal.above_threshold)
        abnormal = scorer.evaluate(prof, {"login_rate": 50.0, "geo": 2.0})
        self.assertGreater(abnormal.score, normal.score)
        self.assertIn("login_rate", abnormal.meaningful_features)


class TestPipeline(unittest.TestCase):
    def _pipe(self):
        return DetectionPipeline()

    def test_noise_suppressed_attack_detected(self):
        pipe = self._pipe()
        for _ in range(40):
            r = pipe.process(_login_event("bob", {
                "failed_logins_1h": 0.2, "impossible_travel_mins": 0.0}))
            self.assertFalse(r.is_incident)
        r = pipe.process(_login_event("bob", {
            "failed_logins_1h": 30.0, "impossible_travel_mins": 8.0,
            "new_geo": 1.0, "new_device": 1.0}))
        self.assertTrue(r.is_incident)
        self.assertIn(r.priority, ("high", "critical"))
        self.assertTrue(r.explanation.attributed_features)
        self.assertTrue(r.reasoning.recommended_actions)

    def test_rule_critical(self):
        pipe = self._pipe()
        evt = Event(event_id="r", ts=0.0, source="edr", entity_id="ws-1",
                    entity_type="device", action="exec", outcome="success",
                    features={"priv_escalation_flag": 1.0,
                              "suspicious_cmdline": 1.0, "lateral_moves_1h": 6.0})
        r = pipe.process(evt)
        self.assertTrue(r.is_incident)
        self.assertEqual(r.priority, "critical")
        self.assertTrue(any(rh.name == "privilege-escalation-suspicious"
                            for rh in r.rule_hits))

    def test_explainer_narrative(self):
        scorer = AnomalyScorer()
        profiler = BaselineProfiler(min_samples=3)
        for i in range(30):
            profiler.observe("e", "user", {"x": 1.0 + (i % 3) * 0.1}, ts=1.0)
        verdict = scorer.evaluate(profiler.profile("e"), {"x": 99.0})
        expl = Explainer().explain(verdict)
        self.assertTrue(expl.attack_path)
        self.assertIn("e", expl.narrative)

    def test_mock_intelligence(self):
        mock = MockIntelligence()
        scorer = AnomalyScorer()
        profiler = BaselineProfiler(min_samples=3)
        for _ in range(20):
            profiler.observe("u", "user", {"failed_logins_1h": 0.0}, ts=1.0)
        verdict = scorer.evaluate(profiler.profile("u"), {"failed_logins_1h": 99.0})
        reasoning = mock.reason(verdict, ["TA0006"])
        self.assertTrue(reasoning.recommended_actions)
        self.assertTrue(0 <= reasoning.confidence <= 1)


if __name__ == "__main__":
    unittest.main()
