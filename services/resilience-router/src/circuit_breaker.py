"""
RESILIENCE ROUTER & CIRCUIT BREAKER
Hystrix Pattern State Machine and Cascading Degradation (72B -> 32B -> 14B)
"""

import time
from enum import Enum
from typing import Dict, Any, Optional

class CircuitState(str, Enum):
    CLOSED = "CLOSED"       # Normal operation (100% to primary Tier-1)
    OPEN = "OPEN"           # Tripped (Redirect all to fallback Tier-2/Tier-3)
    HALF_OPEN = "HALF_OPEN" # Canary testing (Send 5% probe requests)

class ModelTier(str, Enum):
    TIER_1 = "qwen-2.5-72b-instruct"
    TIER_2 = "qwen-2.5-32b-instruct"
    TIER_3 = "qwen-2.5-14b-instruct"

class CircuitBreaker:
    def __init__(
        self,
        failure_threshold_pct: float = 5.0,
        latency_p99_threshold_ms: float = 2500.0,
        cooldown_period_sec: float = 30.0,
        kv_cache_threshold_pct: float = 95.0
    ):
        self.state = CircuitState.CLOSED
        self.failure_threshold_pct = failure_threshold_pct
        self.latency_p99_threshold_ms = latency_p99_threshold_ms
        self.cooldown_period_sec = cooldown_period_sec
        self.kv_cache_threshold_pct = kv_cache_threshold_pct
        
        self.last_state_change = time.time()
        self.request_count = 0
        self.error_count = 0

    def record_result(self, latency_ms: float, is_error: bool, kv_cache_pct: float = 0.0):
        self.request_count += 1
        if is_error:
            self.error_count += 1

        error_rate = (self.error_count / self.request_count) * 100 if self.request_count > 0 else 0

        # State transition logic
        if self.state == CircuitState.CLOSED:
            if error_rate > self.failure_threshold_pct or latency_ms > self.latency_p99_threshold_ms or kv_cache_pct > self.kv_cache_threshold_pct:
                self.trip()
        elif self.state == CircuitState.OPEN:
            if time.time() - self.last_state_change > self.cooldown_period_sec:
                self.half_open()
        elif self.state == CircuitState.HALF_OPEN:
            if not is_error and latency_ms < self.latency_p99_threshold_ms:
                self.reset()
            else:
                self.trip()

    def trip(self):
        self.state = CircuitState.OPEN
        self.last_state_change = time.time()

    def half_open(self):
        self.state = CircuitState.HALF_OPEN
        self.last_state_change = time.time()
        self.request_count = 0
        self.error_count = 0

    def reset(self):
        self.state = CircuitState.CLOSED
        self.last_state_change = time.time()
        self.request_count = 0
        self.error_count = 0

    def select_model(self, requested_model: Optional[str] = None) -> ModelTier:
        """
        Determines the target model tier based on the current circuit health.
        """
        if self.state == CircuitState.CLOSED:
            return ModelTier.TIER_1
        elif self.state == CircuitState.HALF_OPEN:
            # Send small percentage as canary
            return ModelTier.TIER_1 if (self.request_count % 20 == 0) else ModelTier.TIER_2
        else: # OPEN
            return ModelTier.TIER_2
