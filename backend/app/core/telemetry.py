"""
In-memory telemetry store: tracks query counts, latency, errors per provider.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderStats:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: float = 0.0
    latencies: list[float] = field(default_factory=list)

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.total_requests if self.total_requests else 0.0

    @property
    def success_rate(self) -> float:
        return self.successful_requests / self.total_requests if self.total_requests else 0.0


class TelemetryStore:
    """In-process telemetry store for observability and metric calculations."""

    def __init__(self) -> None:
        self._providers: dict[str, ProviderStats] = defaultdict(ProviderStats)
        self._query_count: int = 0
        self._start_time: float = time.time()
        self._errors: list[dict[str, Any]] = []

    def record_query(self, *args, **kwargs) -> None:
        """
        Record a query event.
        Supports both signatures:
          record_query(provider, latency_ms, success=True, error=None)
          record_query(trace_id, latency_ms, provider, tokens=0, confidence_tier="HIGH")
        """
        if len(args) >= 3 and isinstance(args[1], (int, float)) and isinstance(args[2], str):
            # trace_id, latency_ms, provider, [tokens], [confidence]
            _trace_id = str(args[0])
            latency_ms = float(args[1])
            provider = str(args[2])
            success = True
            error = None
        elif len(args) >= 2 and isinstance(args[0], str) and isinstance(args[1], (int, float)):
            provider = str(args[0])
            latency_ms = float(args[1])
            success = bool(args[2]) if len(args) > 2 else kwargs.get("success", True)
            error = args[3] if len(args) > 3 else kwargs.get("error")
        else:
            provider = kwargs.get("provider", "mock")
            latency_ms = float(kwargs.get("latency_ms", 0.0))
            success = bool(kwargs.get("success", True))
            error = kwargs.get("error")

        stats = self._providers[provider]
        stats.total_requests += 1
        stats.total_latency_ms += latency_ms
        stats.latencies.append(latency_ms)
        if success:
            stats.successful_requests += 1
        else:
            stats.failed_requests += 1
        if error:
            self._errors.append({"provider": provider, "error": error, "ts": time.time()})
        self._query_count += 1

    def get_metrics(self) -> dict[str, Any]:
        """Return Prometheus and telemetry-compatible metrics dict."""
        all_lats: list[float] = []
        for s in self._providers.values():
            all_lats.extend(s.latencies)

        if all_lats:
            sorted_lats = sorted(all_lats)
            p95_idx = int(len(sorted_lats) * 0.95)
            p95 = sorted_lats[min(p95_idx, len(sorted_lats) - 1)]
            avg = sum(sorted_lats) / len(sorted_lats)
        else:
            p95 = 0.0
            avg = 0.0

        tot_requests = self._query_count
        tot_fails = sum(s.failed_requests for s in self._providers.values())
        err_rate = tot_fails / tot_requests if tot_requests else 0.0
        uptime = time.time() - self._start_time

        return {
            "total_requests": tot_requests,
            "avg_latency_ms": round(avg, 2),
            "p95_latency_ms": round(p95, 2),
            "error_rate": round(err_rate, 4),
            "error_rate_percent": round(err_rate * 100, 2),
            "hit_ratio_percent": 0.0,
            "uptime_seconds": round(uptime, 1),
            "providers": {
                name: {
                    "calls": s.total_requests,
                    "avg_ms": round(s.avg_latency_ms, 2),
                    "errors": s.failed_requests,
                }
                for name, s in self._providers.items()
            },
            "recent_errors": self._errors[-10:],
        }

    def get_stats(self) -> dict[str, Any]:
        return self.get_metrics()

    def reset(self) -> None:
        self._providers.clear()
        self._query_count = 0
        self._errors.clear()


telemetry_store = TelemetryStore()
