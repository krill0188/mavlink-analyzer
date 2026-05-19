from dataclasses import dataclass, field
from enum import Enum
import statistics
from core.constants import HEARTBEAT_TIMEOUT_SEC

class AnomalyType(str, Enum):
    RTT_SPIKE = "RTT_SPIKE"
    LINK_DOWN = "LINK_DOWN"
    ACK_FAILED = "ACK_FAILED"
    BURST_LOSS = "BURST_LOSS"

@dataclass
class AnomalyEvent:
    timestamp: float
    anomaly_type: str
    severity: str  # 'WARNING' | 'CRITICAL'
    description: str
    src_ip: str
    dst_ip: str = ""
    extra: dict = field(default_factory=dict)

class AnomalyDetector:
    def __init__(self) -> None:
        self._events: list = []

    def analyze_rtt_spikes(self, latency_stats) -> None:
        samples = [s for s in latency_stats.rtt_samples if not s.intermediate]
        if len(samples) < 3:
            return
        rtts = [s.rtt_ms for s in samples]
        mean = statistics.mean(rtts)
        sigma = statistics.stdev(rtts)
        threshold = mean + 3 * sigma
        for s in samples:
            if s.rtt_ms > threshold:
                self._events.append(AnomalyEvent(
                    timestamp=s.timestamp,
                    anomaly_type=AnomalyType.RTT_SPIKE,
                    severity="WARNING",
                    description=f"RTT {s.rtt_ms:.1f}ms (임계: {threshold:.1f}ms, {s.rtt_ms/sigma:.1f}σ)",
                    src_ip=s.src_ip, dst_ip=s.dst_ip,
                    extra={"rtt_ms": s.rtt_ms, "threshold_ms": threshold, "command": s.command_name},
                ))

    def analyze_link_down(self, hb_intervals) -> None:
        threshold_ms = HEARTBEAT_TIMEOUT_SEC * 1000
        for h in hb_intervals:
            if h.interval_ms > threshold_ms:
                severity = "CRITICAL" if h.interval_ms > threshold_ms * 2 else "WARNING"
                self._events.append(AnomalyEvent(
                    timestamp=h.timestamp,
                    anomaly_type=AnomalyType.LINK_DOWN,
                    severity=severity,
                    description=f"HEARTBEAT 단절 {h.interval_ms/1000:.1f}초 (sysid={h.sysid})",
                    src_ip=h.src_ip,
                    extra={"duration_ms": h.interval_ms, "sysid": h.sysid},
                ))

    def analyze_ack_failures(self, rtt_samples) -> None:
        for s in rtt_samples:
            if s.result in (2, 4) and not s.intermediate:  # DENIED, FAILED
                self._events.append(AnomalyEvent(
                    timestamp=s.timestamp,
                    anomaly_type=AnomalyType.ACK_FAILED,
                    severity="CRITICAL",
                    description=f"{s.command_name} → {s.result_name}",
                    src_ip=s.src_ip, dst_ip=s.dst_ip,
                    extra={"command": s.command_name, "result": s.result_name},
                ))

    def analyze_loss_bursts(self, loss_stats) -> None:
        for ls in loss_stats:
            for ev in ls.gap_events:
                if ev["seq_gap"] >= 5:
                    self._events.append(AnomalyEvent(
                        timestamp=ev["timestamp"],
                        anomaly_type=AnomalyType.BURST_LOSS,
                        severity="WARNING",
                        description=f"연속 {ev['seq_gap']}개 패킷 손실 ({ls.stream_key})",
                        src_ip=ev["src"], dst_ip=ev["dst"],
                        extra={"seq_gap": ev["seq_gap"]},
                    ))

    def result(self) -> list:
        return sorted(self._events, key=lambda e: e.timestamp)
