"""
RemediationEngine — 분석 결과 기반 개별/종합 조치 가이드 생성
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class RemStep:
    """단계별 조치 항목"""
    priority: int   # 1=즉시, 2=단기(1주), 3=중기(1개월)
    category: str   # 하드웨어 / 소프트웨어 / 운용 / 환경
    action: str     # 핵심 조치 (한 줄)
    detail: str     # 상세 설명


@dataclass
class IssueRemediation:
    """개별 이슈 + 조치 가이드"""
    key: str
    issue_type: str    # HIGH_LOSS / TRAFFIC_IMBALANCE / RTT_SPIKE / LINK_DOWN / ACK_FAILED / HIGH_JITTER
    severity: str      # CRITICAL / WARNING
    title: str
    affected: str
    summary: str
    impact: str
    steps: List[RemStep] = field(default_factory=list)


@dataclass
class RemediationReport:
    """종합 조치 보고서"""
    issues: List[IssueRemediation]
    immediate_actions: List[str]   # priority=1 집계
    short_term: List[str]          # priority=2 집계
    mid_term: List[str]            # priority=3 집계
    has_critical: bool


class RemediationEngine:
    """분석 결과 → 조치 가이드 변환"""

    def analyze(self, result) -> RemediationReport:
        issues: List[IssueRemediation] = []

        issues.extend(self._check_packet_loss(result.loss))
        issues.extend(self._check_traffic_imbalance(result.endpoints, result.loss))
        issues.extend(self._check_rtt(result.latency))
        issues.extend(self._check_link_down(result.anomalies))
        issues.extend(self._check_ack_failures(result.latency))
        issues.extend(self._check_jitter(result.jitter))

        # 심각도 순 정렬 (CRITICAL 먼저)
        severity_order = {"CRITICAL": 0, "WARNING": 1}
        issues.sort(key=lambda i: severity_order.get(i.severity, 2))

        # 우선순위별 종합 액션 집계 (중복 제거)
        immediate, short_term, mid_term = [], [], []
        seen = set()
        for issue in issues:
            for step in issue.steps:
                key = (step.priority, step.action)
                if key in seen:
                    continue
                seen.add(key)
                entry = f"[{step.category}] {step.action}"
                if step.priority == 1:
                    immediate.append(entry)
                elif step.priority == 2:
                    short_term.append(entry)
                else:
                    mid_term.append(entry)

        return RemediationReport(
            issues=issues,
            immediate_actions=immediate[:10],
            short_term=short_term[:8],
            mid_term=mid_term[:6],
            has_critical=any(i.severity == "CRITICAL" for i in issues),
        )

    # ─────────────────────────────────────────────
    # 1. 패킷 손실
    # ─────────────────────────────────────────────
    def _check_packet_loss(self, loss_list) -> List[IssueRemediation]:
        issues = []
        for ls in loss_list:
            if ls.loss_pct < 0.5:
                continue

            if ls.loss_pct >= 5.0:
                severity = "CRITICAL"
                title = f"심각한 패킷 손실 ({ls.loss_pct:.1f}%)"
                summary = (
                    f"스트림 {ls.stream_key}에서 {ls.loss_pct:.1f}%의 패킷이 유실됩니다. "
                    "드론 제어 신뢰성에 치명적 위험이 있습니다."
                )
                impact = "긴급 명령(RTL/LAND/DISARM) 전달 실패 가능 — 즉시 비행 중단 권고"
                steps = [
                    RemStep(1, "운용",   "즉시 비행 중단 및 안전 착륙",
                            "손실률 5% 이상은 COMMAND 전달 실패 위험. 비행 전 원인 파악 필수"),
                    RemStep(1, "하드웨어", "텔레메트리 안테나 연결 상태 긴급 점검",
                            "SMA 커넥터 풀림, 케이블 단선, 안테나 방향 불량(기체와 수직 정렬) 확인"),
                    RemStep(1, "환경",   "2.4GHz RF 간섭 주파수 스캔 즉시 실시",
                            "Wi-Fi AP·블루투스·다른 RC 시스템과의 채널 충돌 여부 확인, 빈 채널로 변경"),
                    RemStep(1, "소프트웨어", "MAVLink 스트림 레이트 즉시 최소화",
                            "SR0_ALL=0 후 HEARTBEAT(SR0_ADSB)만 1Hz로 설정해 대역폭 확보"),
                    RemStep(2, "하드웨어", "텔레메트리 TX 파워 최대로 증가",
                            "Mission Planner → Setup → Optional Hardware → SiK Radio → Net ID·Tx Power 상향 (Max 20dBm)"),
                    RemStep(2, "환경",   "900MHz 대역 텔레메트리로 교체 검토",
                            "장거리·간섭 환경에서 433/915MHz(RFD900x)가 2.4GHz 대비 회절 특성 우수"),
                    RemStep(2, "소프트웨어", "MAVLink 2.0 서명(Signing) 활성화로 오류 검출 강화",
                            "GCS-FC 양방향 signing 적용 시 손상 패킷 자동 폐기, 재전송 요청"),
                    RemStep(3, "하드웨어", "고신뢰 텔레메트리 모듈로 교체",
                            "RFD900x / Herelink / HolyBro SiK V3 등 FEC(전진오류수정) 내장 모듈 검토"),
                ]

            elif ls.loss_pct >= 2.0:
                severity = "WARNING"
                title = f"패킷 손실 경고 ({ls.loss_pct:.1f}%)"
                summary = (
                    f"스트림 {ls.stream_key}에서 {ls.loss_pct:.1f}% 손실 감지. "
                    "제어 품질이 저하되고 있으며 장거리 임무는 위험합니다."
                )
                impact = "비행 계획 명령 일부 누락 가능 — 장거리/자율 임무 시 위험"
                steps = [
                    RemStep(1, "하드웨어", "안테나 방향 최적화 (수직 정렬 확인)",
                            "드론 텔레메트리 안테나를 기체 하단 방향으로 장착, GCS 안테나도 수직 정렬"),
                    RemStep(1, "환경",   "RF 간섭원 제거 — 운용 반경 내 Wi-Fi 라우터 비활성화",
                            "2.4GHz Wi-Fi·블루투스와 최소 3m 이격, 가능하면 5GHz Wi-Fi로 전환"),
                    RemStep(2, "소프트웨어", "HEARTBEAT 외 불필요 스트림 비활성화",
                            "SR0_EXTRA3, SR0_RC_CHAN, SR0_RAW_CTRL을 0Hz로 설정해 대역폭 여유 확보"),
                    RemStep(2, "하드웨어", "동축 케이블·SMA 커넥터 교체",
                            "50Ω LMR-200 이상 케이블, 산화·부식된 커넥터 교체 (삽입손실 ≤0.5dB/m)"),
                    RemStep(3, "환경",   "자동 안테나 트래커 도입 검토",
                            "장거리 운용 시 방향성 패치 안테나(14dBi) + AAT로 링크 마진 10dB+ 확보"),
                ]

            else:  # 0.5~2%
                severity = "WARNING"
                title = f"패킷 손실 주의 ({ls.loss_pct:.1f}%)"
                summary = (
                    f"스트림 {ls.stream_key}에서 {ls.loss_pct:.1f}% 손실. "
                    "현재는 안전 범위이나 악화 시 즉시 조치 필요."
                )
                impact = "텔레메트리 지연 산발적 발생 — 장시간 비행 시 누적 영향"
                steps = [
                    RemStep(2, "환경",   "정기적 손실률 모니터링 체계 구축",
                            "비행 전후 손실률을 pcap으로 측정해 추이 추적, 2% 초과 시 즉시 점검"),
                    RemStep(2, "하드웨어", "비행 전 체크리스트에 안테나 커넥터 확인 추가",
                            "안테나 SMA 나사 조임, 케이블 킹크(꺾임) 없음 확인"),
                    RemStep(3, "소프트웨어", "손실 패턴과 비행 이벤트 상관관계 분석",
                            "gap_events 타임스탬프와 GPS 좌표를 매핑해 특정 지역/고도에서 악화 여부 파악"),
                ]

            issues.append(IssueRemediation(
                key=f"LOSS_{ls.stream_key}",
                issue_type="HIGH_LOSS",
                severity=severity,
                title=title,
                affected=f"{ls.stream_key} (수신:{ls.total_received:,} / 손실:{ls.lost_count})",
                summary=summary,
                impact=impact,
                steps=steps,
            ))

        return issues

    # ─────────────────────────────────────────────
    # 2. 트래픽 불균형
    # ─────────────────────────────────────────────
    def _check_traffic_imbalance(self, endpoints, loss_list) -> List[IssueRemediation]:
        issues = []
        gcs_eps   = [e for e in endpoints if e.role == "GCS"]
        drone_eps = [e for e in endpoints if e.role == "DRONE"]
        if not gcs_eps or not drone_eps:
            return issues

        gcs_msgs   = sum(e.msg_count for e in gcs_eps)
        drone_msgs = sum(e.msg_count for e in drone_eps)
        total = gcs_msgs + drone_msgs
        if total == 0:
            return issues

        gcs_pct   = gcs_msgs / total * 100
        drone_pct = drone_msgs / total * 100

        if gcs_pct > 70:
            issues.append(IssueRemediation(
                key="IMBALANCE_GCS_HEAVY",
                issue_type="TRAFFIC_IMBALANCE",
                severity="WARNING",
                title=f"GCS→드론 트래픽 편중 (GCS {gcs_pct:.0f}% / 드론 {drone_pct:.0f}%)",
                affected=f"GCS {gcs_msgs:,}건 vs 드론 {drone_msgs:,}건",
                summary=(
                    f"GCS가 전체 트래픽의 {gcs_pct:.0f}%를 차지합니다. "
                    "드론 텔레메트리 응답이 극히 적어 단방향 전송 상태입니다."
                ),
                impact="드론 실시간 상태 모니터링 불가, 단방향 명령만 전송되는 비정상 상태",
                steps=[
                    RemStep(1, "소프트웨어", "FC의 MAVLink 출력 스트림 활성화 확인",
                            "Mission Planner → Config → Full Param List → SR0_ADSB=2, SR0_EXTRA1=4로 설정"),
                    RemStep(1, "운용",   "드론-GCS 물리 연결(TX/RX) 방향 재확인",
                            "텔레메트리 모듈 드론측 TX→GCS측 RX, 드론측 RX→GCS측 TX 크로스 연결 확인"),
                    RemStep(2, "소프트웨어", "MAVLink SYS_STATUS 수신 여부 직접 확인",
                            "Mission Planner 터미널에서 MAVLink Inspector로 드론→GCS 메시지 실수신 검증"),
                    RemStep(2, "하드웨어", "드론측 텔레메트리 모듈 교체 테스트",
                            "동일 모델 모듈 쌍으로 로컬 루프백 테스트 후 불량 모듈 식별"),
                ],
            ))

        elif drone_pct > 75:
            issues.append(IssueRemediation(
                key="IMBALANCE_DRONE_HEAVY",
                issue_type="TRAFFIC_IMBALANCE",
                severity="WARNING",
                title=f"드론→GCS 트래픽 편중 (드론 {drone_pct:.0f}% / GCS {gcs_pct:.0f}%)",
                affected=f"드론 {drone_msgs:,}건 vs GCS {gcs_msgs:,}건",
                summary=(
                    f"드론이 전체 트래픽의 {drone_pct:.0f}%를 차지합니다. "
                    "과도한 텔레메트리 전송으로 대역폭 포화 위험이 있습니다."
                ),
                impact="대역폭 포화 → 명령 전달 지연, GCS 제어 응답성 저하",
                steps=[
                    RemStep(1, "소프트웨어", "텔레메트리 스트림 레이트 즉시 최적화",
                            "SR0_EXTRA1~3·SR0_POSITION·SR0_RAW_SENS를 4~5Hz 이하로 제한"),
                    RemStep(1, "소프트웨어", "불필요한 센서 원시 데이터 스트림 비활성화",
                            "SR0_RAW_CTRL, SR0_RC_CHAN을 0Hz로 설정 — 임무에 불필요한 경우"),
                    RemStep(2, "소프트웨어", "총 대역폭 예산 계산 및 스트림 레이트 재배분",
                            "SiK 57.6kbps 기준 총 메시지/초를 ~20msg/s 이내로 제한"),
                    RemStep(3, "하드웨어", "고대역폭 텔레메트리 링크 업그레이드 검토",
                            "SiK 57.6kbps → RFD900x 250kbps 또는 LTE MAVLink 브리지 도입"),
                ],
            ))

        return issues

    # ─────────────────────────────────────────────
    # 3. RTT 스파이크
    # ─────────────────────────────────────────────
    def _check_rtt(self, latency) -> List[IssueRemediation]:
        issues = []
        if not latency or not latency.rtt_samples:
            return issues

        mean = latency.mean_rtt_ms or 0
        if mean <= 50:
            return issues

        if mean > 300:
            severity, grade_label = "CRITICAL", "위험 수준"
        elif mean > 100:
            severity, grade_label = "WARNING", "경고 수준"
        else:
            severity, grade_label = "WARNING", "주의 수준"

        finals = [s for s in latency.rtt_samples if not s.intermediate]
        spike_count = sum(1 for s in finals if s.rtt_ms > 300)
        spike_pct   = spike_count / max(len(finals), 1) * 100

        issues.append(IssueRemediation(
            key="RTT_HIGH",
            issue_type="RTT_SPIKE",
            severity=severity,
            title=f"커맨드 응답 지연 {grade_label} (평균 {mean:.0f}ms)",
            affected=f"RTT 샘플 {len(finals)}건, 스파이크(>300ms) {spike_count}건 ({spike_pct:.0f}%)",
            summary=(
                f"평균 RTT가 {mean:.0f}ms로 정상(50ms) 대비 "
                f"{mean/50:.1f}배 높습니다."
            ),
            impact="ARM/DISARM/RTL 등 긴급 명령 지연, 자율비행 웨이포인트 정밀도 저하",
            steps=[
                RemStep(1, "소프트웨어", "텔레메트리 스트림 레이트 즉시 50% 감소",
                        "SR0_* 파라미터를 현재 설정의 절반으로 낮춰 링크 부하 경감"),
                RemStep(1, "환경",   "RF 간섭 채널 변경 (2.4GHz 라우터 채널 충돌 제거)",
                        "Wi-Fi 채널 1·6·11과 SiK 라디오 채널이 겹치지 않도록 조정"),
                RemStep(2, "하드웨어", "텔레메트리 TX 파워 최대 설정",
                        "SiK 라디오 AT&T 명령으로 Tx Power=20dBm(최대) 설정"),
                RemStep(2, "소프트웨어", "COMMAND_LONG 재전송 타임아웃 조정",
                        "GCS에서 COMMAND_ACK 대기 시간을 평균 RTT의 5배 이상으로 설정"),
                RemStep(2, "소프트웨어", "MAVLink 2.0 활성화로 패킷 오버헤드 감소",
                        "v1 12바이트 헤더 → v2 10바이트, 서명/트리밍으로 전송 효율 향상"),
                RemStep(3, "하드웨어", "고성능 텔레메트리로 업그레이드",
                        "RFD900x(250kbps/FEC) 또는 Herelink(2.4GHz OFDM, ~10km) 도입 검토"),
            ],
        ))

        return issues

    # ─────────────────────────────────────────────
    # 4. 링크 단절 (LINK_DOWN)
    # ─────────────────────────────────────────────
    def _check_link_down(self, anomalies) -> List[IssueRemediation]:
        issues = []
        link_downs = [a for a in anomalies if "LINK_DOWN" in str(a.anomaly_type)]
        if not link_downs:
            return issues

        critical_downs = [a for a in link_downs if a.severity == "CRITICAL"]
        max_gap_ms = 0
        for a in link_downs:
            extra = a.extra if isinstance(a.extra, dict) else {}
            max_gap_ms = max(max_gap_ms, extra.get("gap_ms", 0))

        severity = "CRITICAL" if critical_downs else "WARNING"
        count = len(link_downs)

        issues.append(IssueRemediation(
            key="LINK_DOWN",
            issue_type="LINK_DOWN",
            severity=severity,
            title=f"HEARTBEAT 링크 단절 {count}회 발생 (최대 {max_gap_ms/1000:.1f}초)",
            affected=f"{count}회 단절, 최대 {max_gap_ms/1000:.1f}초",
            summary=(
                f"HEARTBEAT 신호가 {count}회 3초 이상 단절됐습니다. "
                "FC의 GCS Failsafe가 발동되어 자동 복귀/착륙했을 수 있습니다."
            ),
            impact="자동 Failsafe 발동(RTL/착륙) 위험, 임무 강제 중단 가능성",
            steps=[
                RemStep(1, "운용",   "Failsafe 동작 여부 FC 로그(BIN)로 즉시 확인",
                        "Mission Planner DataFlash 로그에서 FS_GCS 이벤트 및 모드 전환 확인"),
                RemStep(1, "소프트웨어", "FS_GCS_ENABLE Failsafe 타임아웃 5초로 여유 확보",
                        "ArduPilot: FS_GCS_ENABL=2(RTL), FS_GCS_TIMEOUT=5 / PX4: COM_DL_LOSS_T=5"),
                RemStep(1, "하드웨어", "텔레메트리 전원 공급 안정성 긴급 점검",
                        "배터리 전압 강하 시 텔레메트리 전원 차단 여부 확인, 5V 별도 BEC 또는 UBEC 사용"),
                RemStep(2, "환경",   "링크 단절 발생 위치·시각 매핑",
                        "단절 타임스탬프와 GPS 좌표를 겹쳐서 RF 음영 구간(건물/산) 파악"),
                RemStep(2, "하드웨어", "텔레메트리 안테나 위치 최적화",
                        "드론 기체 하부 또는 측면 장착, 프레임 카본/금속 차폐 영향 최소화"),
                RemStep(3, "환경",   "RF 릴레이 스테이션 또는 메쉬 네트워크 도입",
                        "산악·도심 환경에서 중계국 설치(RFD900x 브리지)로 음영 구간 제거"),
            ],
        ))

        return issues

    # ─────────────────────────────────────────────
    # 5. ACK 실패 (DENIED / FAILED)
    # ─────────────────────────────────────────────
    def _check_ack_failures(self, latency) -> List[IssueRemediation]:
        issues = []
        if not latency or not latency.rtt_samples:
            return issues

        failed = [s for s in latency.rtt_samples
                  if not s.intermediate and s.result in (2, 4)]
        if not failed:
            return issues

        denied = [s for s in failed if s.result == 2]
        fail   = [s for s in failed if s.result == 4]

        cmd_cnt: dict = {}
        for s in failed:
            cmd_cnt[s.command_name] = cmd_cnt.get(s.command_name, 0) + 1
        top_cmds = sorted(cmd_cnt.items(), key=lambda x: -x[1])[:3]
        top_str  = ", ".join(f"{c}({n}회)" for c, n in top_cmds)

        denied_steps = [
            RemStep(1, "소프트웨어", "DENIED 커맨드 파라미터 유효성 검증",
                    "거부된 명령의 파라미터값이 FC 허용 범위 내인지 확인 (예: TAKEOFF 고도 0 입력 시 거부)"),
            RemStep(1, "운용",   "FC 현재 모드와 명령 호환성 확인",
                    "AUTO 모드에서만 수락되는 명령을 STABILIZE에서 전송하면 DENIED — 모드 전환 후 재시도"),
        ] if denied else []

        fail_steps = [
            RemStep(1, "운용",   "FAILED 커맨드 실행 전제 조건 점검",
                    "ARM 상태·안전 스위치·배터리 전압·GPS Fix 등 실행 전제 조건 모두 충족 여부 확인"),
        ] if fail else []

        issues.append(IssueRemediation(
            key="ACK_FAILED",
            issue_type="ACK_FAILED",
            severity="CRITICAL",
            title=f"커맨드 실패 {len(failed)}건 (DENIED {len(denied)} / FAILED {len(fail)})",
            affected=top_str or "알 수 없음",
            summary=(
                f"{len(failed)}개 커맨드가 드론에 의해 거부·실패했습니다. "
                f"주요 실패 커맨드: {top_str}"
            ),
            impact="비행 모드 전환·이착륙·임무 명령 불이행 — 자율비행 안전에 직접 위협",
            steps=[
                RemStep(1, "운용",   "FC 모드·ARM 상태 확인 후 명령 재전송",
                        "COMMAND_LONG 전송 전 드론이 GUIDED/AUTO 모드이고 ARM 상태인지 확인"),
                RemStep(1, "소프트웨어", "프리플라이트 체크(GPS·캘리브레이션) 완료 확인",
                        "GPS ≥6위성, 가속도계·자이로 캘리브레이션, 기압계 정상, EKF 수렴 확인"),
                *denied_steps,
                *fail_steps,
                RemStep(2, "소프트웨어", "ArduPilot ARMING_CHECK 파라미터 검토",
                        "ARMING_CHECK=1(전체)에서 운용 환경에 맞게 항목 선택적 비활성화 고려"),
                RemStep(2, "운용",   "GCS-FC 펌웨어 버전 호환성 확인",
                        "구형 FC 펌웨어에서 신규 MAVLink 명령(MAV_CMD_*) 미지원 가능 — 펌웨어 업데이트"),
            ],
        ))

        return issues

    # ─────────────────────────────────────────────
    # 6. HEARTBEAT 지터
    # ─────────────────────────────────────────────
    def _check_jitter(self, jitter_list) -> List[IssueRemediation]:
        issues = []
        for j in jitter_list:
            if j.grade in ("GREEN", "YELLOW"):
                continue

            severity = "CRITICAL" if j.grade == "RED" else "WARNING"
            issues.append(IssueRemediation(
                key=f"JITTER_SYS{j.sysid}",
                issue_type="HIGH_JITTER",
                severity=severity,
                title=f"HEARTBEAT 지터 {j.grade} (σ={j.stddev_ms:.0f}ms, SysID {j.sysid})",
                affected=f"SysID {j.sysid} ({j.src_ip}), 평균 {j.mean_interval_ms}ms 간격",
                summary=(
                    f"HEARTBEAT 간격 표준편차가 {j.stddev_ms:.0f}ms입니다. "
                    "정상은 30ms 미만이어야 합니다."
                ),
                impact="FC 처리 지연 또는 링크 불안정 → GCS의 링크 상태 오판 및 Failsafe 오발동",
                steps=[
                    RemStep(1, "소프트웨어", "FC CPU 부하 점검 (비전/컴퍼니언 컴퓨터 연산 확인)",
                            "고화소 카메라·딥러닝 추론이 MAVLink 스케줄러 방해 여부 확인"),
                    RemStep(2, "소프트웨어", "MAVLink 스트림 전체 레이트 감소",
                            "총 telemetry 대역폭을 줄여 HEARTBEAT 1Hz 정시 전송 보장"),
                    RemStep(2, "하드웨어", "Companion Computer 연산 최적화",
                            "GPU 가속 활용, 비전 파이프라인을 별도 CPU 코어에 격리 실행"),
                    RemStep(3, "소프트웨어", "HEARTBEAT 전용 직렬 포트 분리",
                            "텔레메트리 스트림과 HEARTBEAT를 별도 UART 포트로 분리해 우선순위 보장"),
                ],
            ))

        return issues
