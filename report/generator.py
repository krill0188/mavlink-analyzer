from __future__ import annotations
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any
import json
import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape
from core.constants import worst_grade, grade_rtt, grade_loss, MAV_RESULT_NAMES


@dataclass
class PcapMeta:
    filename: str
    start_time: float
    end_time: float
    duration_sec: float
    total_frames: int
    mavlink_messages: int

    @property
    def start_dt(self) -> str:
        return datetime.datetime.fromtimestamp(self.start_time).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def duration_str(self) -> str:
        h, r = divmod(int(self.duration_sec), 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


@dataclass
class StatusTextEntry:
    timestamp: float
    sysid: int
    severity: int
    severity_name: str
    text: str
    src_ip: str

    @staticmethod
    def severity_label(v: int) -> str:
        labels = {0:"EMERGENCY",1:"ALERT",2:"CRITICAL",3:"ERROR",4:"WARNING",5:"NOTICE",6:"INFO",7:"DEBUG"}
        return labels.get(v, f"SEV_{v}")

    @classmethod
    def from_msg(cls, msg) -> "StatusTextEntry":
        raw = msg.raw_msg
        sev = getattr(raw, 'severity', 6)
        return cls(
            timestamp=msg.timestamp,
            sysid=msg.sysid,
            severity=sev,
            severity_name=cls.severity_label(sev),
            text=getattr(raw, 'text', '').rstrip('\x00'),
            src_ip=msg.src_ip,
        )


@dataclass
class GPSPoint:
    timestamp: float
    lat: float
    lon: float
    alt_m: float
    fix_type: int
    satellites: int

    @classmethod
    def from_msg(cls, msg) -> "GPSPoint":
        raw = msg.raw_msg
        return cls(
            timestamp=msg.timestamp,
            lat=getattr(raw, 'lat', 0) / 1e7,
            lon=getattr(raw, 'lon', 0) / 1e7,
            alt_m=getattr(raw, 'alt', 0) / 1000.0,
            fix_type=getattr(raw, 'fix_type', 0),
            satellites=getattr(raw, 'satellites_visible', 0),
        )


@dataclass
class AnalysisResult:
    pcap_meta: PcapMeta
    endpoints: list
    latency: Any
    loss: list
    jitter: list
    bandwidth: Any
    anomalies: list
    statustexts: list
    gps_track: list


def _safe_serialize(obj):
    if hasattr(obj, '__dataclass_fields__'):
        return asdict(obj)
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    return str(obj)


class ReportGenerator:
    def __init__(self, result: AnalysisResult) -> None:
        self._result = result
        tmpl_dir = Path(__file__).parent
        self._env = Environment(
            loader=FileSystemLoader(str(tmpl_dir)),
            autoescape=select_autoescape(["html"]),
        )
        self._env.filters["grade_color"] = self._grade_color
        self._env.filters["grade_rtt_color"] = lambda v: "#ff3366" if v > 300 else "#ff8800" if v > 100 else "#ffdd00" if v > 50 else "#00ff88"
        self._env.filters["ms_fmt"] = lambda v: f"{v:.1f}ms" if v else "—"
        self._env.filters["pct_fmt"] = lambda v: f"{v:.2f}%"
        self._env.filters["ts_rel"] = self._ts_rel
        self._env.filters["mav_result"] = lambda v: MAV_RESULT_NAMES.get(v, str(v))
        self._base_ts = result.pcap_meta.start_time

    @staticmethod
    def _grade_color(grade: str) -> str:
        return {"GREEN":"#00ff88","YELLOW":"#ffdd00","ORANGE":"#ff8800","RED":"#ff3366"}.get(grade,"#888")

    def _ts_rel(self, ts: float) -> str:
        delta = ts - self._base_ts
        m, s = divmod(int(delta), 60)
        return f"{m:02d}:{s:02d}.{int((delta % 1)*10)}"

    def to_html(self, output_path) -> None:
        template = self._env.get_template("template.html")
        ctx = self._build_context()
        html = template.render(**ctx)
        Path(output_path).write_text(html, encoding="utf-8")

    def to_json(self, output_path) -> None:
        data = self._build_json_data()
        Path(output_path).write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=_safe_serialize),
            encoding="utf-8"
        )

    def _build_context(self) -> dict:
        r = self._result
        overall = self._compute_overall_grade()

        from analyzers.remediation import RemediationEngine
        rem = RemediationEngine().analyze(r)

        return {
            "meta": r.pcap_meta,
            "endpoints": r.endpoints,
            "latency": r.latency,
            "loss": r.loss,
            "jitter": r.jitter,
            "bandwidth": r.bandwidth,
            "anomalies": r.anomalies,
            "statustexts": r.statustexts,
            "gps_track": r.gps_track,
            "overall_grade": overall,
            "overall_color": self._grade_color(overall),
            "report_json": json.dumps(self._build_chart_data(), default=_safe_serialize),
            "has_gps": len(r.gps_track) > 0,
            "has_rtt": len(r.latency.rtt_samples) > 0,
            "has_cmd": len(r.latency.cmd_rtt_table) > 0,
            "remediation": rem,
            "has_remediation": len(rem.issues) > 0,
        }

    def _build_chart_data(self) -> dict:
        r = self._result
        lat = r.latency
        bw = r.bandwidth

        # RTT 시계열
        final_rtt = [s for s in lat.rtt_samples if not s.intermediate]
        rtt_data = {
            "x": [s.timestamp - self._base_ts for s in final_rtt],
            "y": [s.rtt_ms for s in final_rtt],
            "labels": [s.command_name for s in final_rtt],
            "results": [s.result_name for s in final_rtt],
        }

        # HB 간격 히스토그램
        hb_data = [h.interval_ms for h in lat.hb_intervals]

        # 대역폭 시계열
        bw_data = {
            "x": [b.second - self._base_ts for b in bw.buckets],
            "y": [b.msg_count for b in bw.buckets],
            "bytes": [b.byte_count for b in bw.buckets],
        }

        # 메시지 타입 파이
        type_dist = bw.type_distribution

        # 패킷 손실 게이지
        loss_data = [
            {"label": ls.stream_key, "pct": ls.loss_pct, "grade": ls.grade,
             "received": ls.total_received, "lost": ls.lost_count}
            for ls in r.loss
        ]

        # GPS 궤적
        gps_data = [
            {"lat": p.lat, "lon": p.lon, "alt": p.alt_m, "ts": p.timestamp - self._base_ts}
            for p in r.gps_track
        ]

        # ACK 성공/실패
        cmd_results = {}
        for s in final_rtt:
            cmd_results[s.result_name] = cmd_results.get(s.result_name, 0) + 1

        return {
            "rtt": rtt_data,
            "hb_intervals": hb_data,
            "bandwidth": bw_data,
            "type_dist": type_dist,
            "loss": loss_data,
            "gps": gps_data,
            "cmd_results": cmd_results,
        }

    def _build_json_data(self) -> dict:
        r = self._result
        return {
            "meta": {
                "filename": r.pcap_meta.filename,
                "start": r.pcap_meta.start_dt,
                "duration": r.pcap_meta.duration_str,
                "total_frames": r.pcap_meta.total_frames,
                "mavlink_messages": r.pcap_meta.mavlink_messages,
            },
            "endpoints": [
                {"ip": e.ip, "port": e.port, "sysid": e.sysid,
                 "compid": e.compid, "role": e.role, "msg_count": e.msg_count}
                for e in r.endpoints
            ],
            "latency": {
                "mean_rtt_ms": r.latency.mean_rtt_ms,
                "max_rtt_ms": r.latency.max_rtt_ms,
                "min_rtt_ms": r.latency.min_rtt_ms,
                "stddev_rtt_ms": r.latency.stddev_rtt_ms,
                "unanswered_count": r.latency.unanswered_count,
                "cmd_table": r.latency.cmd_rtt_table,
            },
            "loss": [
                {"stream": ls.stream_key, "loss_pct": ls.loss_pct, "grade": ls.grade}
                for ls in r.loss
            ],
            "anomalies": [
                {"time": a.timestamp, "type": a.anomaly_type, "severity": a.severity,
                 "description": a.description}
                for a in r.anomalies
            ],
        }

    def _compute_overall_grade(self) -> str:
        grades = []
        r = self._result
        grades.append(grade_rtt(r.latency.mean_rtt_ms) if r.latency.mean_rtt_ms else "GREEN")
        for ls in r.loss:
            grades.append(grade_loss(ls.loss_pct))
        if r.anomalies:
            critical_count = sum(1 for a in r.anomalies if a.severity == "CRITICAL")
            if critical_count > 0:
                grades.append("RED")
            elif len(r.anomalies) > 0:
                grades.append("YELLOW")
        return worst_grade(*grades) if grades else "GREEN"
