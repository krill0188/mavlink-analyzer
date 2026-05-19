#!/usr/bin/env python3
"""
MAVLink pcap 분석 툴
사용법:
  python analyze.py --pcap capture.pcap
  python analyze.py --pcap capture.pcap --output report.html
  python analyze.py --pcap capture.pcap --format json
  python analyze.py --pcap capture.pcap --format both --no-browser
"""
import sys
import argparse
import json
import webbrowser
import datetime
from pathlib import Path

# 경로 설정
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

from core.pcap_loader import PcapLoader
from core.mavlink_parser import MAVLinkParser
from analyzers.endpoint import EndpointClassifier
from analyzers.latency import LatencyAnalyzer
from analyzers.loss import LossAnalyzer
from analyzers.jitter import JitterAnalyzer
from analyzers.bandwidth import BandwidthAnalyzer
from analyzers.anomaly import AnomalyDetector
from report.generator import (
    ReportGenerator, AnalysisResult, PcapMeta,
    StatusTextEntry, GPSPoint
)


def parse_args():
    p = argparse.ArgumentParser(
        prog="mavlink-analyzer",
        description="MAVLink pcap → HTML/JSON 분석 보고서",
    )
    p.add_argument("--pcap", required=True, help=".pcap/.pcapng 파일 경로")
    p.add_argument("--output", default=None, help="출력 파일 경로")
    p.add_argument("--format", default="html", choices=["html", "json", "both"])
    p.add_argument("--no-browser", action="store_true", help="브라우저 자동 열기 비활성화")
    p.add_argument("--quiet", action="store_true", help="진행 표시 비활성화")
    return p.parse_args()


def run_analysis(pcap_path: Path, quiet: bool = False) -> AnalysisResult:
    loader = PcapLoader(pcap_path)
    parser = MAVLinkParser()
    endpoint = EndpointClassifier()
    latency = LatencyAnalyzer()
    loss = LossAnalyzer()
    jitter = JitterAnalyzer()
    bandwidth = BandwidthAnalyzer()
    statustexts = []
    gps_points = []

    start_ts = None
    end_ts = None
    total_mavlink = 0

    frames = loader.iter_mavlink_frames(show_progress=not quiet)
    for msg in parser.parse(frames):
        if start_ts is None:
            start_ts = msg.timestamp
        end_ts = msg.timestamp
        total_mavlink += 1

        endpoint.feed(msg)
        latency.feed(msg)
        loss.feed(msg)
        jitter.feed(msg)
        bandwidth.feed(msg)

        if msg.msg_name == "STATUSTEXT":
            statustexts.append(StatusTextEntry.from_msg(msg))
        elif msg.msg_name == "GPS_RAW_INT":
            raw = msg.raw_msg
            lat_val = getattr(raw, 'lat', 0) / 1e7
            lon_val = getattr(raw, 'lon', 0) / 1e7
            # 유효 GPS만 (0,0) 제외
            if abs(lat_val) > 0.001 or abs(lon_val) > 0.001:
                gps_points.append(GPSPoint.from_msg(msg))

    endpoint.classify_all()

    lat_result = latency.result()
    loss_result = loss.result()

    anomaly = AnomalyDetector()
    anomaly.analyze_rtt_spikes(lat_result)
    anomaly.analyze_link_down(lat_result.hb_intervals)
    anomaly.analyze_ack_failures(lat_result.rtt_samples)
    anomaly.analyze_loss_bursts(loss_result)

    loader_stats = loader.stats()
    start_ts = start_ts or 0.0
    end_ts = end_ts or 0.0

    meta = PcapMeta(
        filename=pcap_path.name,
        start_time=start_ts,
        end_time=end_ts,
        duration_sec=end_ts - start_ts,
        total_frames=loader_stats["total_packets"],
        mavlink_messages=total_mavlink,
    )

    return AnalysisResult(
        pcap_meta=meta,
        endpoints=endpoint.get_endpoints(),
        latency=lat_result,
        loss=loss_result,
        jitter=jitter.result(),
        bandwidth=bandwidth.result(),
        anomalies=anomaly.result(),
        statustexts=statustexts,
        gps_track=gps_points[:2000],  # 최대 2000포인트
    )


def main() -> int:
    args = parse_args()
    pcap_path = Path(args.pcap)

    if not pcap_path.exists():
        print(f"[ERROR] 파일 없음: {pcap_path}", file=sys.stderr)
        return 1

    output_path = Path(args.output) if args.output else pcap_path.with_suffix(".html")

    if not args.quiet:
        print(f"[*] MAVLink Analyzer 시작")
        print(f"[*] 파일: {pcap_path}")

    try:
        result = run_analysis(pcap_path, quiet=args.quiet)
    except Exception as e:
        print(f"[ERROR] 분석 실패: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    gen = ReportGenerator(result)

    if args.format in ("html", "both"):
        html_path = output_path.with_suffix(".html")
        gen.to_html(html_path)
        if not args.quiet:
            print(f"[+] HTML 보고서: {html_path}")
        if not args.no_browser:
            webbrowser.open(html_path.resolve().as_uri())

    if args.format in ("json", "both"):
        json_path = output_path.with_suffix(".json")
        gen.to_json(json_path)
        if not args.quiet:
            print(f"[+] JSON 보고서: {json_path}")

    if not args.quiet:
        print(f"\n[요약]")
        print(f"  총 패킷: {result.pcap_meta.total_frames:,}")
        print(f"  MAVLink: {result.pcap_meta.mavlink_messages:,}")
        print(f"  엔드포인트: {len(result.endpoints)}")
        print(f"  RTT 샘플: {len(result.latency.rtt_samples)}")
        print(f"  이상 이벤트: {len(result.anomalies)}")
        print(f"  STATUSTEXT: {len(result.statustexts)}")
        print(f"  GPS 포인트: {len(result.gps_track)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
