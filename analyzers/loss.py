from dataclasses import dataclass, field
from collections import defaultdict
from core.constants import grade_loss

@dataclass
class LossStats:
    stream_key: str
    sysid: int
    compid: int
    total_received: int
    lost_count: int
    loss_pct: float
    gap_events: list
    grade: str

class _SeqTracker:
    def __init__(self):
        self.last_seq = None
        self.received = 0
        self.lost = 0
        self.gap_events = []

    def update(self, seq: int, timestamp: float, src_ip: str, dst_ip: str) -> None:
        self.received += 1
        if self.last_seq is None:
            self.last_seq = seq
            return
        expected = (self.last_seq + 1) % 256
        gap = (seq - expected) % 256
        if 0 < gap < 128:
            self.lost += gap
            self.gap_events.append({
                "timestamp": timestamp,
                "seq_gap": gap,
                "expected_seq": expected,
                "got_seq": seq,
                "src": src_ip,
                "dst": dst_ip,
            })
        self.last_seq = seq

class LossAnalyzer:
    def __init__(self) -> None:
        self._trackers: dict = defaultdict(lambda: _SeqTracker())

    def feed(self, msg) -> None:
        key = (msg.sysid, msg.compid, msg.src_ip, msg.dst_ip)
        self._trackers[key].update(msg.seq, msg.timestamp, msg.src_ip, msg.dst_ip)

    def result(self) -> list:
        results = []
        for (sysid, compid, src, dst), t in self._trackers.items():
            total_expected = t.received + t.lost
            loss_pct = (t.lost / total_expected * 100) if total_expected > 0 else 0.0
            results.append(LossStats(
                stream_key=f"{src} → {dst}",
                sysid=sysid, compid=compid,
                total_received=t.received,
                lost_count=t.lost,
                loss_pct=round(loss_pct, 3),
                gap_events=t.gap_events[:50],  # 최대 50개
                grade=grade_loss(loss_pct),
            ))
        return sorted(results, key=lambda x: x.loss_pct, reverse=True)
