from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

MAVLINK_UDP_PORTS: frozenset = frozenset({14550, 14551, 5760, 14540, 18570, 14580})
MAVLINK_TCP_PORTS: frozenset = frozenset({5760, 14550})
MAVLINK_V1_MAGIC = 0xFE
MAVLINK_V2_MAGIC = 0xFD

@dataclass(frozen=True)
class RTTThresholds:
    green_ms: float = 50.0
    yellow_ms: float = 100.0
    orange_ms: float = 300.0

@dataclass(frozen=True)
class LossThresholds:
    green_pct: float = 0.5
    yellow_pct: float = 2.0
    orange_pct: float = 5.0

@dataclass(frozen=True)
class JitterThresholds:
    green_ms: float = 30.0
    yellow_ms: float = 80.0
    orange_ms: float = 150.0

RTT_THRESHOLDS = RTTThresholds()
LOSS_THRESHOLDS = LossThresholds()
JITTER_THRESHOLDS = JitterThresholds()
HEARTBEAT_TIMEOUT_SEC = 3.0
COMMAND_TIMEOUT_SEC = 5.0

class MavResult(IntEnum):
    ACCEPTED = 0
    TEMP_REJECTED = 1
    DENIED = 2
    UNSUPPORTED = 3
    FAILED = 4
    IN_PROGRESS = 5
    CANCELLED = 6

MAV_RESULT_NAMES: dict = {v.value: v.name for v in MavResult}

MAV_CMD_NAMES: dict = {
    16: "NAV_WAYPOINT",
    17: "NAV_LOITER_UNLIM",
    20: "NAV_RETURN_TO_LAUNCH",
    21: "NAV_LAND",
    22: "NAV_TAKEOFF",
    84: "NAV_VTOL_TAKEOFF",
    85: "NAV_VTOL_LAND",
    176: "DO_SET_MODE",
    178: "DO_CHANGE_SPEED",
    179: "DO_SET_HOME",
    400: "COMPONENT_ARM_DISARM",
    410: "GET_HOME_POSITION",
    511: "SET_MESSAGE_INTERVAL",
    520: "REQUEST_MESSAGE",
}

GCS_SYSIDS: frozenset = frozenset({255, 254})

def grade_rtt(rtt_ms: float) -> str:
    t = RTT_THRESHOLDS
    if rtt_ms < t.green_ms: return "GREEN"
    if rtt_ms < t.yellow_ms: return "YELLOW"
    if rtt_ms < t.orange_ms: return "ORANGE"
    return "RED"

def grade_loss(loss_pct: float) -> str:
    t = LOSS_THRESHOLDS
    if loss_pct < t.green_pct: return "GREEN"
    if loss_pct < t.yellow_pct: return "YELLOW"
    if loss_pct < t.orange_pct: return "ORANGE"
    return "RED"

def grade_jitter(jitter_ms: float) -> str:
    t = JITTER_THRESHOLDS
    if jitter_ms < t.green_ms: return "GREEN"
    if jitter_ms < t.yellow_ms: return "YELLOW"
    if jitter_ms < t.orange_ms: return "ORANGE"
    return "RED"

GRADE_PRIORITY = {"RED": 4, "ORANGE": 3, "YELLOW": 2, "GREEN": 1}

def worst_grade(*grades: str) -> str:
    return max(grades, key=lambda g: GRADE_PRIORITY.get(g, 0))
