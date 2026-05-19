from dataclasses import dataclass
from collections import defaultdict
import statistics
from core.constants import grade_jitter

@dataclass
class JitterStats:
    sysid: int
    src_ip: str
    mean_interval_ms: float
    stddev_ms: float
    max_interval_ms: float
    min_interval_ms: float
    interval_series: list
    timestamps: list
    grade: str

class JitterAnalyzer:
    def __init__(self) -> None:
        self._data: dict = defaultdict(list)  # (sysid, src_ip) → [(ts, interval_ms)]
        self._last_hb: dict = {}

    def feed(self, msg) -> None:
        if msg.msg_name != "HEARTBEAT":
            return
        key = (msg.sysid, msg.src_ip)
        if key in self._last_hb:
            interval_ms = (msg.timestamp - self._last_hb[key]) * 1000
            self._data[key].append((msg.timestamp, interval_ms))
        self._last_hb[key] = msg.timestamp

    def result(self) -> list:
        results = []
        for (sysid, src_ip), series in self._data.items():
            if not series:
                continue
            intervals = [s[1] for s in series]
            timestamps = [s[0] for s in series]
            stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            results.append(JitterStats(
                sysid=sysid, src_ip=src_ip,
                mean_interval_ms=round(statistics.mean(intervals), 2),
                stddev_ms=round(stddev, 2),
                max_interval_ms=round(max(intervals), 2),
                min_interval_ms=round(min(intervals), 2),
                interval_series=intervals,
                timestamps=timestamps,
                grade=grade_jitter(stddev),
            ))
        return results
