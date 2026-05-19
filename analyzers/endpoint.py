from dataclasses import dataclass, field
from collections import defaultdict
from core.constants import GCS_SYSIDS

@dataclass
class Endpoint:
    ip: str
    port: int
    sysid: int
    compid: int
    role: str = "UNKNOWN"  # 'GCS' | 'DRONE' | 'UNKNOWN'
    msg_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    msg_types: set = field(default_factory=set)

class EndpointClassifier:
    def __init__(self) -> None:
        self._endpoints: dict = {}  # (ip, port) → Endpoint
        self._sysid_roles: dict = {}  # sysid → 'GCS'|'DRONE'
        self._first_hb_sysid: dict = {}  # sysid → timestamp (first HEARTBEAT)

    def feed(self, msg) -> None:
        key = (msg.src_ip, msg.src_port)
        if key not in self._endpoints:
            self._endpoints[key] = Endpoint(
                ip=msg.src_ip, port=msg.src_port,
                sysid=msg.sysid, compid=msg.compid,
                first_seen=msg.timestamp,
            )
        ep = self._endpoints[key]
        ep.msg_count += 1
        ep.byte_count += msg.byte_size
        ep.last_seen = msg.timestamp
        ep.msg_types.add(msg.msg_name)

        # HEARTBEAT로 GCS/드론 판별
        if msg.msg_name == "HEARTBEAT":
            raw = msg.raw_msg
            mav_type = getattr(raw, 'type', -1)
            sysid = msg.sysid
            if sysid not in self._first_hb_sysid:
                self._first_hb_sysid[sysid] = msg.timestamp
            if mav_type == 6:  # MAV_TYPE_GCS
                self._sysid_roles[sysid] = "GCS"
            elif sysid in GCS_SYSIDS:
                self._sysid_roles[sysid] = "GCS"
            else:
                if sysid not in self._sysid_roles:
                    self._sysid_roles[sysid] = "DRONE"

    def classify_all(self) -> None:
        GCS_PORTS = {14550, 14551}
        for (ip, port), ep in self._endpoints.items():
            sysid_role = self._sysid_roles.get(ep.sysid)
            if sysid_role:
                ep.role = sysid_role
            elif ep.sysid in GCS_SYSIDS:
                ep.role = "GCS"
            elif port in GCS_PORTS:
                ep.role = "GCS"
            else:
                ep.role = "DRONE"

    def get_endpoints(self) -> list:
        return sorted(self._endpoints.values(), key=lambda e: e.msg_count, reverse=True)
