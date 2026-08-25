"""Backpressure & circuit-breaker tests (stdlib unittest — no external deps)."""

import os
import sys
import time
import threading
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from aegisflow.bus.resilient_queue import (  # noqa: E402
    BackpressureBuffer,
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    ResilientBus,
    backoff_retry,
)


class TestBuffer(unittest.TestCase):
    def test_basic_put_get(self):
        buf = BackpressureBuffer(capacity=10, high_watermark=0.8, low_watermark=0.3)
        for i in range(5):
            self.assertTrue(buf.put(i))
        batch = buf.get_many(3, timeout_s=0.05)
        self.assertEqual(batch, [0, 1, 2])
        self.assertEqual(buf.size, 2)

    def test_drop_oldest(self):
        buf = BackpressureBuffer(capacity=4, high_watermark=0.8, low_watermark=0.3, blocking=False)
        for i in range(10):
            buf.put(i)
        self.assertEqual(buf.size, 4)
        self.assertEqual(buf.dropped, 6)
        batch = buf.get_many(10, timeout_s=0.02)
        self.assertEqual(batch, [6, 7, 8, 9])

    def test_blocking_backpressure(self):
        buf = BackpressureBuffer(capacity=10, high_watermark=0.8, low_watermark=0.3, blocking=True)
        produced = []

        def producer():
            for i in range(50):
                buf.put(i)
                produced.append(i)

        def consumer():
            time.sleep(0.05)
            for _ in range(50):
                batch = buf.get_many(5, timeout_s=0.02)
                if not batch:
                    break

        p = threading.Thread(target=producer)
        c = threading.Thread(target=consumer)
        p.start(); c.start()
        p.join(2); c.join(2)
        self.assertEqual(len(produced), 50)
        self.assertEqual(buf.dropped, 0)

    def test_put_nowait_full_blocking(self):
        buf = BackpressureBuffer(capacity=3, high_watermark=0.8, low_watermark=0.3, blocking=True)
        for i in range(3):
            self.assertTrue(buf.put_nowait(i))
        self.assertFalse(buf.put_nowait(99))


class TestCircuitBreaker(unittest.TestCase):
    def test_opens_then_recovers(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_s=0.1)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            raise ValueError("boom")

        for _ in range(3):
            with self.assertRaises(ValueError):
                cb.call(flaky)
        self.assertEqual(cb.state, CircuitState.OPEN)
        with self.assertRaises(CircuitBreakerOpenError):
            cb.call(flaky)
        before = calls["n"]
        time.sleep(0.15)
        with self.assertRaises(ValueError):
            cb.call(flaky)
        self.assertEqual(calls["n"], before + 1)

    def test_retry_succeeds(self):
        attempts = {"n": 0}

        def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise IOError("transient")
            return "ok"

        self.assertEqual(backoff_retry(flaky, attempts=3, base_delay_s=0.001), "ok")
        self.assertEqual(attempts["n"], 3)


class TestResilientBus(unittest.TestCase):
    def test_publish_drain(self):
        bus = ResilientBus(capacity=100, batch_size=10)
        for i in range(25):
            bus.publish(i)
        self.assertEqual(bus.snapshot().produced, 25)
        received = []

        def handler(batch):
            received.extend(batch)

        bus.process(handler, max_items=1000, max_iterations=10)
        self.assertEqual(len(received), 25)
        self.assertEqual(bus.snapshot().consumed, 25)

    def test_circuit_degrade(self):
        bus = ResilientBus(
            capacity=100, batch_size=5,
            circuit=CircuitBreaker(failure_threshold=2, cooldown_s=100))
        for i in range(20):
            bus.publish(i)

        def explode(batch):
            raise RuntimeError("downstream down")

        bus.process(explode, max_items=1000, max_iterations=20)
        stats = bus.snapshot()
        self.assertGreater(stats.dropped, 0)
        self.assertEqual(stats.consumed, 0)
        self.assertEqual(stats.circuit_state, CircuitState.OPEN)


if __name__ == "__main__":
    unittest.main()
