from dataclasses import dataclass, field
from collections import defaultdict, Counter
import math

@dataclass
class BandwidthBucket:
    second: int
    msg_count: int = 0
    byte_count: int = 0
    msg_types: dict = field(default_factory=dict)

@dataclass
class BandwidthStats:
    buckets: list
    peak_msg_per_sec: int
    mean_msg_per_sec: float
    peak_bytes_per_sec: int
    type_distribution: dict

class BandwidthAnalyzer:
    def __init__(self) -> None:
        self._buckets: dict = {}  # second (int) → BandwidthBucket
        self._total_types: Counter = Counter()

    def feed(self, msg) -> None:
        sec = int(math.floor(msg.timestamp))
        if sec not in self._buckets:
            self._buckets[sec] = BandwidthBucket(second=sec)
        b = self._buckets[sec]
        b.msg_count += 1
        b.byte_count += msg.byte_size
        b.msg_types[msg.msg_name] = b.msg_types.get(msg.msg_name, 0) + 1
        self._total_types[msg.msg_name] += 1

    def result(self) -> BandwidthStats:
        buckets = sorted(self._buckets.values(), key=lambda b: b.second)
        counts = [b.msg_count for b in buckets]
        return BandwidthStats(
            buckets=buckets,
            peak_msg_per_sec=max(counts) if counts else 0,
            mean_msg_per_sec=round(sum(counts) / len(counts), 2) if counts else 0.0,
            peak_bytes_per_sec=max(b.byte_count for b in buckets) if buckets else 0,
            type_distribution=dict(self._total_types.most_common(20)),
        )
