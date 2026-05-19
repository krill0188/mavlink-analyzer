from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from tqdm import tqdm

from .constants import MAVLINK_UDP_PORTS, MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC

@dataclass
class RawMAVFrame:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str  # 'UDP' | 'TCP'
    payload: bytes

class PcapLoader:
    def __init__(self, path) -> None:
        self.path = Path(path)
        self._total = 0
        self._mavlink = 0

    def iter_mavlink_frames(self, show_progress: bool = True) -> Iterator[RawMAVFrame]:
        from scapy.all import PcapReader, UDP, TCP, IP, IPv6

        with PcapReader(str(self.path)) as reader:
            pbar = tqdm(desc="패킷 분석", unit="pkt", disable=not show_progress)
            for pkt in reader:
                self._total += 1
                pbar.update(1)

                frame = self._extract_frame(pkt, UDP, TCP, IP, IPv6)
                if frame:
                    self._mavlink += 1
                    yield frame
            pbar.close()

    def _extract_frame(self, pkt, UDP, TCP, IP, IPv6):
        # IP 레이어 확인
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None

        if UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if not self._is_mavlink_port(sport, dport):
                return None
            payload = bytes(pkt[UDP].payload)
            if not payload:
                return None
            # MAVLink 매직 바이트 포함 여부 빠른 체크
            if not any(b in (MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC) for b in payload[:4]):
                return None
            return RawMAVFrame(
                timestamp=float(pkt.time),
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=sport, dst_port=dport,
                transport="UDP", payload=payload,
            )

        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload)
            if not payload:
                return None
            return RawMAVFrame(
                timestamp=float(pkt.time),
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=sport, dst_port=dport,
                transport="TCP", payload=payload,
            )
        return None

    @staticmethod
    def _is_mavlink_port(src: int, dst: int) -> bool:
        return bool({src, dst} & MAVLINK_UDP_PORTS)

    def stats(self) -> dict:
        return {"total_packets": self._total, "mavlink_frames": self._mavlink}
