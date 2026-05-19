from dataclasses import dataclass, field
from typing import Iterator

from .constants import MAVLINK_V1_MAGIC, MAVLINK_V2_MAGIC

@dataclass
class MAVMessage:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    transport: str
    sysid: int
    compid: int
    msg_name: str
    mavlink_v: int  # 1 or 2
    seq: int
    raw_msg: object  # pymavlink 원본
    byte_size: int

class MAVLinkParser:
    def __init__(self) -> None:
        self._mav_instances: dict = {}
        self._parsed = 0
        self._errors = 0

    def parse(self, frames: Iterator) -> Iterator[MAVMessage]:
        for frame in frames:
            if frame.transport == "UDP":
                yield from self._parse_udp(frame)
            else:
                yield from self._parse_tcp(frame)

    def _parse_udp(self, frame) -> list:
        results = []
        mav = self._get_mav(f"{frame.src_ip}:{frame.src_port}")
        # parse_char()는 내부 상태머신 — 페이로드 전체를 순서대로 공급
        for b in frame.payload:
            try:
                msg = mav.parse_char(bytes([b]))
                if msg and msg.get_type() != "BAD_DATA":
                    v = 2 if getattr(msg, '_header', None) and hasattr(msg._header, 'incompat_flags') else 1
                    results.append(self._wrap(msg, frame, v))
                    self._parsed += 1
            except Exception:
                self._errors += 1
        return results

    def _parse_tcp(self, frame) -> list:
        key = (frame.src_ip, frame.src_port, frame.dst_ip, frame.dst_port)
        # 새 페이로드만 추가 후 신규 바이트만 파싱 (O(n) 유지)
        new_data = frame.payload
        results = []

        mav = self._get_mav(f"{frame.src_ip}:{frame.src_port}")
        for b in new_data:
            try:
                msg = mav.parse_char(bytes([b]))
                if msg and msg.get_type() != "BAD_DATA":
                    v = 2 if getattr(msg, '_header', None) and hasattr(msg._header, 'incompat_flags') else 1
                    results.append(self._wrap(msg, frame, v))
                    self._parsed += 1
            except Exception:
                self._errors += 1

        return results

    def _get_mav(self, key: str):
        if key not in self._mav_instances:
            try:
                from pymavlink.dialects.v20 import ardupilotmega as mav2
            except ImportError:
                from pymavlink.dialects.v20 import common as mav2
            inst = mav2.MAVLink(None)
            inst.robust_parsing = True
            self._mav_instances[key] = inst
        return self._mav_instances[key]

    def _wrap(self, msg, frame, v: int) -> MAVMessage:
        hdr = getattr(msg, '_header', None)
        seq = hdr.seq if hdr and hasattr(hdr, 'seq') else 0
        mlen = hdr.mlen if hdr and hasattr(hdr, 'mlen') else 0
        return MAVMessage(
            timestamp=frame.timestamp,
            src_ip=frame.src_ip, dst_ip=frame.dst_ip,
            src_port=frame.src_port, dst_port=frame.dst_port,
            transport=frame.transport,
            sysid=msg.get_srcSystem(),
            compid=msg.get_srcComponent(),
            msg_name=msg.get_type(),
            mavlink_v=v,
            seq=seq,
            raw_msg=msg,
            byte_size=mlen + (10 if v == 2 else 6),
        )

    def stats(self) -> dict:
        return {"parsed": self._parsed, "errors": self._errors}
