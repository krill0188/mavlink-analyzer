from dataclasses import dataclass, field
from collections import defaultdict, deque
from core.constants import MAV_RESULT_NAMES, MAV_CMD_NAMES, grade_rtt, COMMAND_TIMEOUT_SEC
import statistics

@dataclass
class RTTSample:
    timestamp: float
    command_id: int
    command_name: str
    rtt_ms: float
    result: int
    result_name: str
    src_ip: str
    dst_ip: str
    intermediate: bool = False

@dataclass
class HeartbeatInterval:
    timestamp: float
    interval_ms: float
    sysid: int
    src_ip: str

@dataclass
class LatencyStats:
    rtt_samples: list
    hb_intervals: list
    mean_rtt_ms: float
    max_rtt_ms: float
    min_rtt_ms: float
    stddev_rtt_ms: float
    mean_hb_interval_ms: float
    cmd_rtt_table: list
    unanswered_count: int

class LatencyAnalyzer:
    def __init__(self) -> None:
        # (src_ip, dst_ip, command_id) → deque of {'time', 'cmd_name'}
        self._pending: dict = defaultdict(lambda: deque(maxlen=32))
        self._rtt_samples: list = []
        self._hb_intervals: list = []
        self._last_hb: dict = {}  # (src_ip, sysid) → last_timestamp
        self._unanswered = 0

    def feed(self, msg) -> None:
        if msg.msg_name == "COMMAND_LONG":
            self._on_command_long(msg)
        elif msg.msg_name == "COMMAND_ACK":
            self._on_command_ack(msg)
        elif msg.msg_name == "HEARTBEAT":
            self._on_heartbeat(msg)

    def _on_command_long(self, msg) -> None:
        raw = msg.raw_msg
        cmd_id = getattr(raw, 'command', 0)
        key = (msg.src_ip, msg.dst_ip, cmd_id)
        self._pending[key].append({
            "time": msg.timestamp,
            "cmd_name": MAV_CMD_NAMES.get(cmd_id, f"CMD_{cmd_id}"),
            "src_ip": msg.src_ip,
            "dst_ip": msg.dst_ip,
        })

    def _on_command_ack(self, msg) -> None:
        raw = msg.raw_msg
        cmd_id = getattr(raw, 'command', 0)
        result = getattr(raw, 'result', -1)
        # ACK는 src/dst 방향이 역전됨
        key = (msg.dst_ip, msg.src_ip, cmd_id)

        if key in self._pending and self._pending[key]:
            entry = self._pending[key].popleft()
            rtt_ms = (msg.timestamp - entry["time"]) * 1000

            if result == 5:  # IN_PROGRESS → intermediate 기록 후 큐에 돌려넣기
                self._rtt_samples.append(RTTSample(
                    timestamp=entry["time"], command_id=cmd_id,
                    command_name=entry["cmd_name"], rtt_ms=rtt_ms,
                    result=result, result_name=MAV_RESULT_NAMES.get(result, str(result)),
                    src_ip=entry["src_ip"], dst_ip=entry["dst_ip"],
                    intermediate=True,
                ))
                self._pending[key].appendleft(entry)  # 최종 ACK 대기
            else:
                self._rtt_samples.append(RTTSample(
                    timestamp=entry["time"], command_id=cmd_id,
                    command_name=entry["cmd_name"], rtt_ms=rtt_ms,
                    result=result, result_name=MAV_RESULT_NAMES.get(result, str(result)),
                    src_ip=entry["src_ip"], dst_ip=entry["dst_ip"],
                ))

    def _on_heartbeat(self, msg) -> None:
        hb_key = (msg.src_ip, msg.sysid)
        if hb_key in self._last_hb:
            interval_ms = (msg.timestamp - self._last_hb[hb_key]) * 1000
            self._hb_intervals.append(HeartbeatInterval(
                timestamp=msg.timestamp,
                interval_ms=interval_ms,
                sysid=msg.sysid,
                src_ip=msg.src_ip,
            ))
        self._last_hb[hb_key] = msg.timestamp

    def result(self) -> LatencyStats:
        # 미응답 커맨드 카운트
        self._unanswered = sum(len(q) for q in self._pending.values())

        final_samples = [s for s in self._rtt_samples if not s.intermediate]
        rtts = [s.rtt_ms for s in final_samples]
        hb_ints = [h.interval_ms for h in self._hb_intervals]

        # 커맨드별 집계
        cmd_map = defaultdict(list)
        for s in final_samples:
            cmd_map[s.command_name].append(s)
        cmd_table = []
        for cmd_name, samples in sorted(cmd_map.items()):
            rtt_list = [s.rtt_ms for s in samples]
            success_count = sum(1 for s in samples if s.result == 0)
            cmd_table.append({
                "command": cmd_name,
                "count": len(samples),
                "mean_rtt_ms": round(statistics.mean(rtt_list), 1),
                "max_rtt_ms": round(max(rtt_list), 1),
                "min_rtt_ms": round(min(rtt_list), 1),
                "success_rate": round(success_count / len(samples) * 100, 1),
            })

        return LatencyStats(
            rtt_samples=self._rtt_samples,
            hb_intervals=self._hb_intervals,
            mean_rtt_ms=round(statistics.mean(rtts), 2) if rtts else 0.0,
            max_rtt_ms=round(max(rtts), 2) if rtts else 0.0,
            min_rtt_ms=round(min(rtts), 2) if rtts else 0.0,
            stddev_rtt_ms=round(statistics.stdev(rtts), 2) if len(rtts) > 1 else 0.0,
            mean_hb_interval_ms=round(statistics.mean(hb_ints), 1) if hb_ints else 0.0,
            cmd_rtt_table=cmd_table,
            unanswered_count=self._unanswered,
        )
