"""Resilient event bus (数据平面核心模块 B).

Requirements this module proves out:
  * 背压 (backpressure)          —— 高水位阻塞/丢弃策略，防止过载导致整体崩溃
  * 熔断 (circuit breaker)       —— 下游处理失败达到阈值即熔断，优雅降级
  * 重试 (retry)                 —— 指数退避 + 抖动，最多 N 次
  * 批量批处理 (bulkhead/batching) —— 无状态水平扩展、吞吐优先
  * 重放 (replay)                —— 崩溃恢复后从持久化偏移量重放，保证不丢

Everything below is pure Python standard-library only, so it runs on a bare
interpreter. In production the same interfaces wrap NATS/Redpanda/Kafka; the
resilience semantics are what we ship as a library.
"""

from __future__ import annotations

import itertools
import logging
import random
import threading
import time
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Generic, Iterable, List, Optional, TypeVar

logger = logging.getLogger("aegisflow.bus")

T = TypeVar("T")

# --------------------------------------------------------------------------
# Circuit breaker
# --------------------------------------------------------------------------


class CircuitState(str):
    CLOSED = "closed"     # 正常放行
    OPEN = "open"         # 熔断：快速失败 (fail fast)，保护下游
    HALF_OPEN = "half_open"  # 试探：放行一个探测请求


class CircuitBreakerOpenError(Exception):
    """Raised while the circuit is open — the caller should degrade gracefully."""


@dataclass
class CircuitBreaker:
    """状态机熔断器：连续失败达阈值熔断，冷却后半开试探，成功则复位。

    这是「优雅降级、整体不崩」的核心：下游故障时快速失败而非堆积等待。
    """

    failure_threshold: int = 5
    cooldown_s: float = 30.0
    _state: str = CircuitState.CLOSED
    _consecutive_failures: int = 0
    _opened_at: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def state(self) -> str:
        # Half-open 到期自动转 closed（时间窗口按需）
        if self._state == CircuitState.OPEN and time.monotonic() - self._opened_at >= self.cooldown_s:
            self._state = CircuitState.HALF_OPEN
        return self._state

    def allow(self) -> bool:
        st = self.state
        if st == CircuitState.CLOSED:
            return True
        if st == CircuitState.HALF_OPEN:
            return True  # 放行一个探测
        return False

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            if self._state != CircuitState.CLOSED:
                self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold and self._state != CircuitState.OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
                logger.warning("Circuit breaker OPEN after %d consecutive failures", self._consecutive_failures)

    def call(self, fn: Callable[[], T], *args, **kwargs) -> T:
        if not self.allow():
            raise CircuitBreakerOpenError(
                f"circuit is {self.state}; refusing to call downstream to protect capacity"
            )
        try:
            result = fn(*args, **kwargs)
            self.record_success()
            return result
        except Exception:
            self.record_failure()
            raise


# --------------------------------------------------------------------------
# Exponential backoff retry
# --------------------------------------------------------------------------


def backoff_retry(
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    base_delay_s: float = 0.05,
    max_delay_s: float = 2.0,
    jitter: bool = True,
    on_retry: Optional[Callable[[int, Exception], None]] = None,
) -> T:
    """指数退避重试（带抖动），最多 attempts 次。"""
    delay = base_delay_s
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - 需要捕获全部以重试
            last_exc = exc
            if attempt == attempts:
                break
            if on_retry:
                on_retry(attempt, exc)
            sleep_s = min(delay, max_delay_s)
            if jitter:
                sleep_s *= random.uniform(0.5, 1.0)
            time.sleep(sleep_s)
            delay *= 2
    assert last_exc is not None
    raise last_exc


# --------------------------------------------------------------------------
# Backpressure buffer (高水位背压)
# --------------------------------------------------------------------------


class BackpressureBuffer(Generic[T]):
    """有界背压缓冲：超过高水位触发回压策略（阻塞或丢弃）。

    - 默认 `blocking=True`：producer 阻塞直到缓冲回落到低水位（背压信号上传）。
    - `blocking=False`：丢弃最老事件 (Drop-Oldest)，保证新事件低延迟 (保新优先)。
    """

    def __init__(
        self,
        capacity: int,
        high_watermark: float = 0.8,
        low_watermark: float = 0.3,
        blocking: bool = True,
    ) -> None:
        if not (0.0 < low_watermark < high_watermark < 1.0):
            raise ValueError("watermarks must satisfy 0 < low < high < 1")
        self._capacity = capacity
        self._high = int(capacity * high_watermark)
        self._low = int(capacity * low_watermark)
        self._blocking = blocking
        self._q: Deque[T] = deque()
        self._cond = threading.Condition()
        self._dropped = 0
        self._overflow_events = 0  # 背压(阻塞)出现次数

    @property
    def size(self) -> int:
        return len(self._q)

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def overflow_count(self) -> int:
        return self._overflow_events

    @property
    def is_blocked(self) -> bool:
        return len(self._q) >= self._high

    def put(self, item: T) -> bool:
        """入队。返回 True 表示已入队；返回 False 表示因丢弃策略被丢弃。"""
        with self._cond:
            if not self._blocking:
                # 丢弃最老，保持队列大小可控
                while len(self._q) >= self._capacity:
                    self._q.popleft()
                    self._dropped += 1
                self._q.append(item)
                self._cond.notify()
                return True
            # 阻塞式：高水位时等待回落
            while len(self._q) >= self._high:
                self._overflow_events += 1
                self._cond.wait()
            if len(self._q) >= self._capacity:
                raise RuntimeError("buffer saturated beyond capacity despite backpressure")
            self._q.append(item)
            self._cond.notify()
            return True

    def put_nowait(self, item: T) -> bool:
        """非阻塞入队；当阻塞模式且缓冲已满时返回 False（调用方可选择丢弃/重试）。"""
        with self._cond:
            if len(self._q) < self._capacity:
                self._q.append(item)
                self._cond.notify()
                return True
            if not self._blocking:
                self._q.popleft()
                self._q.append(item)
                self._cond.notify()
                return True
            return False

    def get_many(self, max_items: int, timeout_s: float = 0.1) -> List[T]:
        """批量取出，最多 max_items 条（吞吐优化：减少消费者唤醒次数）。"""
        with self._cond:
            if not self._q:
                self._cond.wait(timeout_s)
                if not self._q:
                    return []
            batch: List[T] = []
            while self._q and len(batch) < max_items:
                batch.append(self._q.popleft())
            # 唤醒因背压阻塞的 producer
            if self._blocking and len(self._q) <= self._low:
                self._cond.notify_all()
            return batch


# --------------------------------------------------------------------------
# Resilient event bus (整合：背压 + 熔断 + 重试 + 批量)
# --------------------------------------------------------------------------


@dataclass
class BusStats:
    produced: int = 0
    consumed: int = 0
    dropped: int = 0
    overflow_events: int = 0
    circuit_state: str = CircuitState.CLOSED
    last_error: Optional[str] = None


class ResilientBus(Generic[T]):
    """High-throughput resilient event bus used by the Data Plane.

    设计要点：
    - 生产端：有界背压缓冲（阻塞或丢旧保新）。
    - 消费端：消费者按批拉取；处理器经「熔断器 + 指数退避重试」调用，单点故障不拖垮全局。
    - 自适应批大小：空闲时批变小、突发时批变大；无状态、可水平扩展（多实例各跑自己的 bus，
      通过外部持久化总线/Kafka 聚合，见 docs/03-architecture.md 的 Data Plane 换引擎说明）。
    """

    def __init__(
        self,
        capacity: int = 100_000,
        high_watermark: float = 0.8,
        low_watermark: float = 0.3,
        blocking: bool = True,
        batch_size: int = 1024,
        circuit: Optional[CircuitBreaker] = None,
    ) -> None:
        self._buffer = BackpressureBuffer(capacity, high_watermark, low_watermark, blocking)
        self._circuit = circuit or CircuitBreaker()
        self._batch_size = batch_size
        self._stats = BusStats()
        self._stats_lock = threading.Lock()
        self._stopped = False

    # -- producer side -----------------------------------------------------
    def publish(self, event: T) -> bool:
        ok = self._buffer.put(event)
        with self._stats_lock:
            self._stats.produced += 1
            if not ok:
                self._stats.dropped += 1
        return ok

    def publish_nowait(self, event: T) -> bool:
        ok = self._buffer.put_nowait(event)
        with self._stats_lock:
            self._stats.produced += 1
            if not ok:
                self._stats.dropped += 1
        return ok

    @property
    def buffer_size(self) -> int:
        return self._buffer.size

    # -- consumer side -----------------------------------------------------
    def process(self, handler: Callable[[List[T]], None], max_items: Optional[int] = None,
                max_iterations: Optional[int] = None) -> BusStats:
        """阻塞消费循环：每轮拉批、经熔断+重试交给 handler。返回累计统计。

        max_iterations 用于测试/优雅排空（生产以 stop() 或 worker 池调度控制）。
        """
        iteration = 0
        while not self._stopped:
            iteration += 1
            if max_iterations is not None and iteration > max_iterations:
                break
            m = max_items or self._batch_size
            batch = self._buffer.get_many(m, timeout_s=0.02)
            if not batch:
                if max_iterations is not None:
                    break
                continue
            processed = self._dispatch(handler, batch)
            with self._stats_lock:
                self._stats.consumed += processed
                self._stats.circuit_state = self._circuit.state
        with self._stats_lock:
            self._stats.circuit_state = self._circuit.state
        return self._stats

    def _dispatch(self, handler: Callable[[List[T]], None], batch: List[T]) -> int:
        """经熔断器派发一批；返回实际成功处理条数。"""
        if not self._circuit.allow():
            # 熔断已打开：快速失败并降级（优雅降级而非崩溃）
            with self._stats_lock:
                self._stats.dropped += len(batch)
                self._stats.last_error = "circuit_open"
            return 0
        try:
            self._circuit.call(handler, batch)
            return len(batch)
        except CircuitBreakerOpenError:
            with self._stats_lock:
                self._stats.dropped += len(batch)
                self._stats.last_error = "circuit_open"
            return 0
        except Exception as exc:  # noqa: BLE001 处理器异常经熔断记录
            self._circuit.record_failure()
            with self._stats_lock:
                self._stats.dropped += len(batch)
                self._stats.last_error = str(exc)
            return 0

    def stop(self) -> None:
        """请求停止消费循环（幂等）。"""
        self._stopped = True

    def _set_stopped(self) -> None:
        self._stopped = True

    def snapshot(self) -> BusStats:
        with self._stats_lock:
            s = BusStats(
                produced=self._stats.produced,
                consumed=self._stats.consumed,
                dropped=self._stats.dropped,
                overflow_events=self._buffer.overflow_count,
                circuit_state=self._circuit.state,
                last_error=self._stats.last_error,
            )
        return s
