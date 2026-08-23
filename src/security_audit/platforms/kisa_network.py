# ruff: noqa: E501
"""KISA 2026 네트워크 장비 N-01~N-38 개발용 점검 계약.

Guide Catalog의 승인된 원문 위치를 사용하지만 공식 Audit Pack 승인을 뜻하지
않습니다. AOS-CX REST로 충분히 입증되지 않은 항목은 양호로 추정하지 않고
REVIEW 또는 N/A로 유지합니다.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from security_audit.common.canonical_json import JsonValue

from .contracts import AssessmentStatus, DeviceControlResult, EvidenceTrace


@dataclass(frozen=True, slots=True)
class NetworkControlDefinition:
    control_id: str
    title: str
    severity: str
    category: str
    source_pages: str
    safe_criterion: str
    review_requirement: str


def _control(
    number: int,
    title: str,
    severity: str,
    category: str,
    pages: str,
    safe_criterion: str,
    review_requirement: str,
) -> NetworkControlDefinition:
    return NetworkControlDefinition(
        control_id=f"N-{number:02d}",
        title=title,
        severity=severity,
        category=category,
        source_pages=pages,
        safe_criterion=safe_criterion,
        review_requirement=review_requirement,
    )


KISA_NETWORK_CONTROLS = (
    _control(1, "비밀번호 설정", "상", "계정 관리", "391~394", "기본 비밀번호를 변경하고 비밀번호를 설정", "초기 비밀번호 변경 여부"),
    _control(2, "비밀번호 복잡성 설정", "상", "계정 관리", "395~396", "기관 정책에 맞는 비밀번호 복잡성 적용", "기관 비밀번호 정책과 장비 복잡성 설정"),
    _control(3, "암호화된 비밀번호 사용", "상", "계정 관리", "397~398", "비밀번호 암호화 저장", "저장 비밀번호의 비가역·암호화 여부"),
    _control(4, "계정 잠금 임계값 설정", "상", "계정 관리", "399~400", "로그인 실패 임계값 5회 이하", "계정 잠금 임계값과 잠금 동작"),
    _control(5, "사용자·명령어별 권한 설정", "중", "계정 관리", "401~405", "업무별 최소 권한 분리", "계정·역할 목록과 업무별 권한 정책"),
    _control(6, "VTY 접근(ACL) 설정", "상", "접근 관리", "406~409", "관리 접속 허용 주소 제한", "VTY 또는 관리 서비스 접근 ACL"),
    _control(7, "Session Timeout 설정", "상", "접근 관리", "410~411", "관리 세션 유휴 제한 10분 이하", "CLI·웹 관리 세션 제한값"),
    _control(8, "VTY 접속 시 안전한 프로토콜 사용", "중", "접근 관리", "412~414", "SSH 사용 및 Telnet 차단", "모든 관리 VRF의 SSH·Telnet 상태"),
    _control(9, "불필요한 보조 입출력 포트 사용 금지", "중", "접근 관리", "415~416", "불필요한 보조 포트 비활성화", "보조·콘솔 포트 사용 필요성"),
    _control(10, "로그인 시 경고 메시지 설정", "중", "접근 관리", "417~418", "시스템 정보가 없는 경고 배너", "로그인 배너 내용과 승인 문구"),
    _control(11, "원격로그 서버 사용", "중", "접근 관리", "419~421", "별도 원격 로그 서버 사용", "활성 원격 syslog 목적지"),
    _control(12, "주기적 보안 패치 및 벤더 권고사항 적용", "상", "패치 관리", "422~423", "보안 패치·벤더 권고의 주기적 검토와 적용", "현재 버전의 권고사항 검토 기록"),
    _control(13, "로깅 버퍼 크기 설정", "중", "로그 관리", "424~425", "발생 로그보다 충분한 버퍼 확보", "로그 발생량과 버퍼 크기 비교"),
    _control(14, "정책에 따른 로깅 설정", "중", "로그 관리", "426~427", "승인된 정책에 따른 보안 이벤트 로깅", "조직 로깅 정책과 장비 필터"),
    _control(15, "NTP 및 시각 동기화 설정", "중", "로그 관리", "428~429", "신뢰 NTP 서버와 실시간 동기화", "NTP client·서버 구성"),
    _control(16, "Timestamp 로그 설정", "하", "로그 관리", "430", "로그 timestamp 기록", "로그 timestamp 형식 설정"),
    _control(17, "SNMP 서비스 확인", "상", "기능 관리", "431~432", "불필요한 SNMP 비활성화", "SNMP 사용 승인 여부"),
    _control(18, "SNMP Community String 복잡성 설정", "상", "기능 관리", "433~434", "SNMP 미사용 또는 복잡한 community", "community 사용 여부와 복잡성"),
    _control(19, "SNMP ACL 설정", "상", "기능 관리", "435~437", "SNMP 미사용 또는 접근 ACL 적용", "SNMP 접근 ACL"),
    _control(20, "SNMP Community 권한 설정", "상", "기능 관리", "438~439", "community 읽기 전용 권한", "community별 접근 권한"),
    _control(21, "TFTP 서비스 차단", "상", "기능 관리", "440", "불필요한 TFTP 차단", "TFTP 서비스 상태"),
    _control(22, "Spoofing 방지 필터링 적용", "상", "기능 관리", "441~443", "경계 인터페이스 spoofing 방지 필터", "경계 인터페이스와 필터 정책"),
    _control(23, "DDoS 공격 방어 설정 또는 DDoS 장비 사용", "상", "기능 관리", "444~445", "DDoS 방어 설정 또는 전용 장비 사용", "DDoS 정책·외부 방어 장비 증적"),
    _control(24, "사용하지 않는 인터페이스 비활성화", "상", "기능 관리", "446~447", "미사용 인터페이스 shutdown", "인터페이스 용도대장과 관리 상태"),
    _control(25, "TCP Keepalive 서비스 설정", "중", "기능 관리", "448", "TCP keepalive 활성화", "TCP keepalive 설정"),
    _control(26, "Finger 서비스 차단", "중", "기능 관리", "449~450", "Finger 서비스 차단", "Finger 서비스 상태"),
    _control(27, "웹 서비스 차단", "중", "기능 관리", "451~452", "불필요한 웹 관리 차단 또는 접근 제한", "웹 관리 필요성·허용 주소"),
    _control(28, "TCP/UDP small 서비스 차단", "중", "기능 관리", "453", "TCP/UDP small 서비스 차단", "small service 상태"),
    _control(29, "Bootp 서비스 차단", "중", "기능 관리", "454~455", "BOOTP 서비스 차단", "BOOTP 서비스 상태"),
    _control(30, "CDP 서비스 차단", "중", "기능 관리", "456", "불필요한 CDP 차단", "CDP 동작 모드"),
    _control(31, "Directed-broadcast 차단", "중", "기능 관리", "457~458", "IP directed broadcast 차단", "인터페이스별 directed broadcast 상태"),
    _control(32, "Source Routing 차단", "중", "기능 관리", "459", "IP source routing 차단", "source routing 상태"),
    _control(33, "Proxy ARP 차단", "중", "기능 관리", "460", "불필요한 proxy ARP 차단", "인터페이스별 proxy ARP 상태"),
    _control(34, "ICMP unreachable, redirect 차단", "중", "기능 관리", "461~462", "ICMP unreachable·redirect 차단", "ICMP unreachable·redirect 상태"),
    _control(35, "identd 서비스 차단", "중", "기능 관리", "463", "identd 서비스 차단", "identd 서비스 상태"),
    _control(36, "Domain Lookup 차단", "중", "기능 관리", "464", "불필요한 domain lookup 차단", "domain lookup 필요성·상태"),
    _control(37, "pad 차단", "중", "기능 관리", "465", "PAD 서비스 차단", "PAD 서비스 상태"),
    _control(38, "mask-reply 차단", "중", "기능 관리", "466", "IP mask reply 차단", "mask reply 상태"),
)

NETWORK_CONTROL_BY_ID = {item.control_id: item for item in KISA_NETWORK_CONTROLS}


@dataclass(frozen=True, slots=True)
class NetworkCriteriaField:
    """REST 수집값과 분리해 저장하는 조직별 구조화 판정 기준."""

    control_id: str
    key: str
    label: str
    input_type: str
    default_value: bool | int
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True, slots=True)
class NetworkSupplementalAssessmentField:
    """장비 REST 확인값과 분리하는 조직 보완 판정 입력."""

    control_id: str
    key: str
    label: str
    default_value: AssessmentStatus = "PASS"


NETWORK_CRITERIA_FIELDS = (
    NetworkCriteriaField("N-04", "login_failure_lock_threshold", "로그인 실패 잠금 허용 상한", "integer", 5, 1, 20),
    NetworkCriteriaField("N-05", "privilege_separation_enabled", "업무별 최소 권한 분리 필수", "boolean", True),
    NetworkCriteriaField("N-09", "auxiliary_ports_disabled", "불필요한 보조 포트 비활성화 필수", "boolean", True),
    NetworkCriteriaField("N-10", "login_warning_banner_enabled", "승인된 로그인 경고 배너 필수", "boolean", True),
    NetworkCriteriaField("N-12", "security_advisories_reviewed", "보안 패치·벤더 권고 정기 검토 필수", "boolean", True),
    NetworkCriteriaField("N-13", "logging_buffer_sufficient", "로그 발생량 대비 충분한 버퍼 필수", "boolean", True),
    NetworkCriteriaField("N-14", "security_event_logging_enabled", "조직 정책에 따른 보안 이벤트 로깅 필수", "boolean", True),
    NetworkCriteriaField("N-16", "log_timestamps_enabled", "로그 timestamp 기록 필수", "boolean", True),
    NetworkCriteriaField("N-17", "snmp_business_use_approved", "SNMP 사용 시 업무 승인 필수", "boolean", True),
    NetworkCriteriaField("N-19", "snmp_access_restricted", "SNMP 접근 대상 제한 필수", "boolean", True),
    NetworkCriteriaField("N-21", "tftp_disabled", "TFTP 서비스 차단 필수", "boolean", True),
    NetworkCriteriaField("N-22", "spoofing_protection_enabled", "Spoofing 방지 필터 필수", "boolean", True),
    NetworkCriteriaField("N-23", "ddos_protection_enabled", "DDoS 방어 설정 또는 장비 필수", "boolean", True),
    NetworkCriteriaField("N-24", "unused_interfaces_disabled", "미사용 인터페이스 비활성화 필수", "boolean", True),
    NetworkCriteriaField("N-25", "tcp_keepalive_enabled", "TCP keepalive 활성화 필수", "boolean", True),
    NetworkCriteriaField("N-26", "finger_disabled", "Finger 서비스 차단 필수", "boolean", True),
    NetworkCriteriaField("N-27", "web_management_restricted", "웹 관리 차단 또는 접근 제한 필수", "boolean", True),
    NetworkCriteriaField("N-28", "small_services_disabled", "TCP/UDP small 서비스 차단 필수", "boolean", True),
    NetworkCriteriaField("N-29", "bootp_disabled", "BOOTP 서비스 차단 필수", "boolean", True),
    NetworkCriteriaField("N-31", "directed_broadcast_disabled", "Directed broadcast 차단 필수", "boolean", True),
    NetworkCriteriaField("N-32", "source_routing_disabled", "Source routing 차단 필수", "boolean", True),
    NetworkCriteriaField("N-33", "proxy_arp_disabled", "불필요한 Proxy ARP 차단 필수", "boolean", True),
    NetworkCriteriaField("N-35", "identd_disabled", "identd 서비스 차단 필수", "boolean", True),
    NetworkCriteriaField("N-36", "domain_lookup_disabled", "불필요한 Domain lookup 차단 필수", "boolean", True),
    NetworkCriteriaField("N-37", "pad_disabled", "PAD 서비스 차단 필수", "boolean", True),
    NetworkCriteriaField("N-38", "mask_reply_disabled", "Mask reply 차단 필수", "boolean", True),
)

_CRITERIA_FIELD_BY_CONTROL = {
    item.control_id: item for item in NETWORK_CRITERIA_FIELDS
}

NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS = (
    NetworkSupplementalAssessmentField("N-12", "n12_patch_advisory_assessment", "보안 패치·벤더 권고 검토"),
    NetworkSupplementalAssessmentField("N-17", "n17_snmp_approval_assessment", "SNMP 업무 사용 승인"),
)

_SUPPLEMENTAL_FIELD_BY_CONTROL = {
    item.control_id: item for item in NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS
}


@dataclass(frozen=True, slots=True)
class KisaNetworkAssessmentProfile:
    """장비 수집값을 덮어쓰지 않는 Switch 조직 판정 기준 profile."""

    login_failure_lock_threshold: int = 5
    privilege_separation_enabled: bool = True
    auxiliary_ports_disabled: bool = True
    login_warning_banner_enabled: bool = True
    security_advisories_reviewed: bool = True
    logging_buffer_sufficient: bool = True
    security_event_logging_enabled: bool = True
    log_timestamps_enabled: bool = True
    snmp_business_use_approved: bool = True
    snmp_access_restricted: bool = True
    tftp_disabled: bool = True
    spoofing_protection_enabled: bool = True
    ddos_protection_enabled: bool = True
    unused_interfaces_disabled: bool = True
    tcp_keepalive_enabled: bool = True
    finger_disabled: bool = True
    web_management_restricted: bool = True
    small_services_disabled: bool = True
    bootp_disabled: bool = True
    directed_broadcast_disabled: bool = True
    source_routing_disabled: bool = True
    proxy_arp_disabled: bool = True
    identd_disabled: bool = True
    domain_lookup_disabled: bool = True
    pad_disabled: bool = True
    mask_reply_disabled: bool = True
    n12_patch_advisory_assessment: AssessmentStatus = "PASS"
    n17_snmp_approval_assessment: AssessmentStatus = "PASS"

    @classmethod
    def from_values(
        cls, values: Mapping[str, object] | None
    ) -> KisaNetworkAssessmentProfile:
        if values is None:
            return cls()
        allowed = {
            item.key
            for item in (
                *NETWORK_CRITERIA_FIELDS,
                *NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS,
            )
        }
        if set(values) != allowed:
            raise ValueError("SWITCH_CRITERIA_KEYS_INVALID")
        normalized: dict[str, bool | int | str] = {}
        for field_definition in NETWORK_CRITERIA_FIELDS:
            value = values.get(field_definition.key)
            if field_definition.input_type == "boolean":
                if not isinstance(value, bool):
                    raise ValueError("SWITCH_CRITERIA_VALUE_INVALID")
            elif (
                not isinstance(value, int)
                or isinstance(value, bool)
                or field_definition.minimum is None
                or field_definition.maximum is None
                or not field_definition.minimum <= value <= field_definition.maximum
            ):
                raise ValueError("SWITCH_CRITERIA_VALUE_INVALID")
            normalized[field_definition.key] = value
        for supplemental_definition in NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS:
            value = values.get(supplemental_definition.key)
            if value not in {"PASS", "FAIL", "REVIEW", "N/A"}:
                raise ValueError("SWITCH_SUPPLEMENTAL_VALUE_INVALID")
            normalized[supplemental_definition.key] = value
        return cls(**cast(Any, normalized))

    def public_values(self) -> dict[str, JsonValue]:
        return {
            item.key: cast(JsonValue, getattr(self, item.key))
            for item in (
                *NETWORK_CRITERIA_FIELDS,
                *NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS,
            )
        }

    def supplemental_values(self) -> dict[str, JsonValue]:
        return {
            item.key: cast(JsonValue, getattr(self, item.key))
            for item in NETWORK_SUPPLEMENTAL_ASSESSMENT_FIELDS
        }

    def supplemental_status(self, control_id: str) -> AssessmentStatus | None:
        field_definition = _SUPPLEMENTAL_FIELD_BY_CONTROL.get(control_id)
        if field_definition is None:
            return None
        return cast(AssessmentStatus, getattr(self, field_definition.key))


def _bool(facts: Mapping[str, JsonValue], key: str) -> bool | None:
    value = facts.get(key)
    return value if isinstance(value, bool) else None


def _int(facts: Mapping[str, JsonValue], key: str) -> int | None:
    value = facts.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _simple_boolean(
    facts: Mapping[str, JsonValue], key: str, enabled: str, disabled: str
) -> tuple[AssessmentStatus, str]:
    value = _bool(facts, key)
    if value is None:
        return "REVIEW", f"{enabled} 여부: REST 증적 없음"
    return ("PASS", enabled) if value else ("FAIL", disabled)


def _evaluate_device(
    definition: NetworkControlDefinition,
    facts: Mapping[str, JsonValue],
    profile: KisaNetworkAssessmentProfile | None,
) -> tuple[AssessmentStatus, str]:
    control_id = definition.control_id
    platform_family = facts.get("platform.family")
    aos_cx_not_applicable = {
        "N-13": "사용자 조정형 로그 버퍼 크기",
        "N-21": "상시 TFTP 서버 서비스",
        "N-25": "전역 TCP keepalive 서비스 설정",
        "N-26": "Finger service",
        "N-28": "TCP/UDP small service",
        "N-29": "BOOTP server",
        "N-32": "IP source routing",
        "N-35": "identd service",
        "N-37": "PAD service",
        "N-38": "IP mask reply",
    }
    if platform_family == "AOS-CX" and control_id in aos_cx_not_applicable:
        return "N/A", f"AOS-CX v10.13 비지원·비적용 기능: {aos_cx_not_applicable[control_id]}"
    if control_id == "N-01":
        return _simple_boolean(facts, "auth.admin_password_set", "관리자 비밀번호 인증: 성공", "관리자 비밀번호 인증: 실패")
    if control_id == "N-02":
        return _simple_boolean(facts, "identity.password_complexity_enabled", "비밀번호 복잡성 기능: 활성화", "비밀번호 복잡성 기능: 비활성화")
    if control_id == "N-03":
        return _simple_boolean(facts, "identity.password_storage_encrypted", "AOS-CX 비밀번호 평문 미노출·보호 저장 방식: 확인", "비밀번호 암호화 저장: 확인 실패")
    if control_id == "N-04":
        attempts = _int(facts, "identity.ssh_maximum_authentication_attempts")
        lock_threshold = profile.login_failure_lock_threshold if profile is not None else 5
        if attempts is None:
            return "REVIEW", "SSH 최대 인증 시도: REST 증적 없음"
        return (
            "PASS" if attempts <= lock_threshold else "FAIL",
            f"SSH 연결당 최대 인증 시도: {attempts}회, 허용 상한: {lock_threshold}회",
        )
    if control_id == "N-05":
        roles = _int(facts, "identity.builtin_role_count")
        rules = _int(facts, "identity.rbac_rule_count")
        users = _int(facts, "identity.user_count")
        administrators = _int(facts, "identity.administrator_user_count")
        non_administrators = _int(facts, "identity.non_administrator_user_count")
        unknown_roles = _int(facts, "identity.unknown_role_user_count")
        if (
            roles is not None
            and rules is not None
            and users is not None
            and administrators is not None
            and non_administrators is not None
            and unknown_roles is not None
        ):
            account_status: AssessmentStatus = (
                "PASS"
                if roles >= 2
                and users > 0
                and non_administrators > 0
                and unknown_roles == 0
                else "FAIL"
            )
            return (
                account_status,
                f"로컬 사용자: {users}개, 관리자: {administrators}개, "
                f"비관리자: {non_administrators}개, 기본 역할: {roles}개, "
                f"역할 미확인: {unknown_roles}개, 사용자 정의 RBAC 규칙: {rules}개",
            )
    if control_id == "N-06":
        enabled = _bool(facts, "management.ssh_allowlist_enabled")
        count = _int(facts, "management.ssh_allowlist_count")
        if enabled is None or count is None:
            return "REVIEW", "관리 접속 허용 목록: REST 증적 없음"
        return (("PASS", f"관리 접속 허용 목록: 활성화, 등록 대역: {count}개") if enabled and count > 0 else ("FAIL", "관리 접속 허용 목록: 비활성화 또는 비어 있음"))
    if control_id == "N-07":
        cli = _int(facts, "management.cli_timeout_minutes")
        web = _int(facts, "management.web_timeout_minutes")
        if cli is None or web is None:
            return "REVIEW", "CLI·웹 관리 세션 제한: 한 개 이상 확인되지 않음"
        status: AssessmentStatus = "PASS" if 1 <= cli <= 10 and 1 <= web <= 10 else "FAIL"
        return status, f"CLI 유휴 제한: {cli}분, 웹 관리 유휴 제한: {web}분"
    if control_id == "N-08":
        ssh = _bool(facts, "management.mgmt_ssh_enabled")
        telnet_count = _int(facts, "management.telnet_enabled_vrf_count")
        if ssh is None or telnet_count is None:
            return "REVIEW", "관리 SSH·Telnet 상태: 일부 REST 증적 없음"
        status = "PASS" if ssh and telnet_count == 0 else "FAIL"
        return status, f"관리 VRF SSH: {'활성화' if ssh else '비활성화'}, Telnet 활성 VRF: {telnet_count}개"
    if control_id == "N-09":
        usb = _bool(facts, "management.usb_auxiliary_disabled")
        bluetooth = _bool(facts, "management.bluetooth_disabled")
        if usb is None or bluetooth is None:
            return "REVIEW", "USB 보조 포트·Bluetooth 관리 상태: REST 증적 없음"
        return (
            ("PASS" if usb else "FAIL"),
            f"USB 보조 포트 차단: {'예' if usb else '아니요'}, Bluetooth 관리 차단: {'예' if bluetooth else '아니요'}",
        )
    if control_id == "N-10":
        configured = _bool(facts, "management.login_banner_configured")
        discloses = _bool(
            facts, "management.login_banner_discloses_system_information"
        )
        if configured is None or discloses is None:
            return "REVIEW", "로그인 경고 배너: REST 증적 없음"
        status = "PASS" if configured and not discloses else "FAIL"
        return (
            status,
            "로그인 경고 배너: "
            f"{'설정' if configured else '미설정'}, 시스템 식별정보 노출: "
            f"{'있음' if discloses else '없음'}",
        )
    if control_id == "N-11":
        count = _int(facts, "logging.remote_server_count")
        if count is None:
            return "REVIEW", "활성 원격 syslog 서버: REST 증적 없음"
        return ("PASS" if count > 0 else "FAIL"), f"활성 원격 syslog 서버: {count}개"
    if control_id == "N-12":
        version = facts.get("platform.software_version")
        patches = _int(facts, "platform.hot_patch_count")
        if isinstance(version, str) and patches is not None:
            return (
                "REVIEW",
                f"실행 소프트웨어: {version}, 설치 hot patch: {patches}개, "
                "벤더 권고 검토 이력은 조직 증적 필요",
            )
    if control_id == "N-13":
        persistent = _bool(facts, "logging.persistent_storage_configured")
        buffer_threshold_configured = _bool(
            facts, "logging.notification_threshold_configured"
        )
        if persistent is not None and buffer_threshold_configured is not None:
            return "REVIEW", f"로그 영구 저장 구성: {'있음' if persistent else '없음'}, 버퍼 임계 알림: {'있음' if buffer_threshold_configured else '없음'}, 발생량 비교 필요"
    if control_id == "N-14":
        remotes = _int(facts, "logging.remote_server_count")
        auditable = _int(facts, "logging.auditable_remote_server_count")
        if remotes is None or auditable is None:
            return "REVIEW", "원격 보안 이벤트 로깅: REST 증적 없음"
        status = "PASS" if remotes > 0 and auditable == remotes else "FAIL"
        return status, f"활성 원격 syslog: {remotes}개, 감사·인증 이벤트 포함: {auditable}개"
    if control_id == "N-15":
        enabled = _bool(facts, "time.ntp_client_enabled")
        count = _int(facts, "time.ntp_server_count")
        if enabled is None or count is None:
            return "REVIEW", "NTP client·서버: 일부 REST 증적 없음"
        return ("PASS" if enabled and count > 0 else "FAIL"), f"NTP client: {'활성화' if enabled else '비활성화'}, 구성 서버: {count}개"
    if control_id == "N-16":
        present = _bool(facts, "logging.event_timestamp_present")
        if present is None:
            return "REVIEW", "최근 이벤트 로그 timestamp: REST 증적 없음"
        return (
            "PASS" if present else "FAIL",
            f"최근 이벤트 로그 timestamp: {'확인' if present else '확인되지 않음'}",
        )
    if control_id == "N-17":
        count = _int(facts, "snmp.enabled_vrf_count")
        if count == 0:
            return "PASS", "SNMP 활성 VRF: 0개"
        if count is not None:
            return "REVIEW", f"SNMP 활성 VRF: {count}개, 업무상 필요성 정책: 확인 필요"
    if control_id == "N-18":
        v3_only = _bool(facts, "snmp.v3_only")
        communities = _int(facts, "snmp.community_count")
        if v3_only and communities == 0:
            return "PASS", "SNMPv3 전용: 활성화, v1/v2 community: 0개"
        if communities is not None and communities > 0:
            return "REVIEW", f"SNMP v1/v2 community: {communities}개, 문자열 원문은 비수집"
    if control_id == "N-19":
        snmp_enabled_count = _int(facts, "snmp.enabled_vrf_count")
        if snmp_enabled_count == 0:
            return "PASS", "SNMP 활성 VRF: 0개"
        non_management = _int(facts, "snmp.non_management_vrf_count")
        v3_only = _bool(facts, "snmp.v3_only")
        users = _int(facts, "snmp.user_count")
        secure_read_only = _int(facts, "snmp.secure_read_only_user_count")
        if (
            snmp_enabled_count is not None
            and non_management is not None
            and v3_only is not None
            and users is not None
            and secure_read_only is not None
        ):
            snmp_status: AssessmentStatus = (
                "PASS"
                if v3_only
                and users > 0
                and secure_read_only == users
                and non_management == 0
                else "FAIL"
            )
            return (
                snmp_status,
                f"SNMP 활성 VRF: {snmp_enabled_count}개, 관리망 외: "
                f"{non_management}개, v3 전용: {'예' if v3_only else '아니요'}, "
                f"인증·암호화 읽기 전용 사용자: {secure_read_only}/{users}개",
            )
    if control_id == "N-20":
        v3_only = _bool(facts, "snmp.v3_only")
        communities = _int(facts, "snmp.community_count")
        if v3_only and communities == 0:
            return "N/A", "SNMPv3 전용 구성으로 v1/v2 community를 사용하지 않음"
        if communities is not None:
            return "REVIEW", f"SNMP v1/v2 community: {communities}개, 권한 원문은 비수집"
    if control_id == "N-22":
        routed = _int(facts, "network.routed_interface_count")
        protected = _int(facts, "network.source_lockdown_interface_count")
        if routed is None or protected is None or routed == 0:
            return "REVIEW", "라우팅·경계 인터페이스의 source lockdown 적용 범위 확인 필요"
        status = "PASS" if protected == routed else "FAIL"
        return status, f"라우팅 인터페이스: {routed}개, source lockdown 적용: {protected}개"
    if control_id == "N-23":
        copp = _bool(facts, "network.copp_effective_policy")
        if copp is not None:
            return (
                "PASS" if copp else "FAIL",
                f"AOS-CX 유효 CoPP 정책: {'확인' if copp else '확인되지 않음'}",
            )
    if control_id == "N-24":
        physical = _int(facts, "network.physical_interface_count")
        active = _int(facts, "network.active_physical_interface_count")
        undocumented = _int(facts, "network.active_undocumented_interface_count")
        if physical is None or active is None or undocumented is None:
            return "REVIEW", "물리 인터페이스 관리 상태·설명: REST 증적 없음"
        if physical == 0:
            return "N/A", "AOS-CX Virtual에 물리 데이터 포트가 없음"
        observed = (
            f"물리 인터페이스: {physical}개, 활성: {active}개, "
            f"활성·용도 미표시: {undocumented}개"
        )
        if undocumented > 0:
            return "FAIL", observed
        if active == 0:
            return "PASS", observed
        return "REVIEW", f"{observed}, 활성 포트의 실제 업무 용도대장 대조 필요"
    if control_id == "N-27":
        https_enabled = _int(facts, "management.https_enabled_vrf_count")
        outside_mgmt = _int(facts, "management.https_non_management_vrf_count")
        if https_enabled is None or outside_mgmt is None:
            return "REVIEW", "HTTPS 관리 활성 VRF: REST 증적 없음"
        status = "PASS" if outside_mgmt == 0 else "FAIL"
        return status, f"HTTPS 관리 활성 VRF: {https_enabled}개, 관리망 외 활성 VRF: {outside_mgmt}개"
    if control_id == "N-30":
        mode = facts.get("discovery.cdp_mode")
        if isinstance(mode, str):
            normalized = mode.casefold()
            return ("PASS" if normalized in {"disable", "disabled", "off"} else "FAIL"), f"CDP 동작 모드: {normalized}"
    if control_id == "N-31":
        directed_broadcasts = _int(
            facts, "network.directed_broadcast_enabled_count"
        )
        if directed_broadcasts is not None:
            return (
                "PASS" if directed_broadcasts == 0 else "FAIL"
            ), f"Directed broadcast 활성 인터페이스: {directed_broadcasts}개"
    if control_id == "N-33":
        proxy_arp_interfaces = _int(facts, "network.proxy_arp_enabled_count")
        if proxy_arp_interfaces is not None:
            return (
                "PASS" if proxy_arp_interfaces == 0 else "FAIL"
            ), f"Proxy ARP 활성 인터페이스: {proxy_arp_interfaces}개"
    if control_id == "N-34":
        unreachable = _bool(facts, "network.icmp_unreachable_disabled")
        redirect = _bool(facts, "network.icmp_redirect_disabled")
        if unreachable is not None and redirect is not None:
            status = "PASS" if unreachable and redirect else "FAIL"
            return status, f"ICMP unreachable 차단: {'예' if unreachable else '아니요'}, redirect 차단: {'예' if redirect else '아니요'}"
    if control_id == "N-36":
        servers = _int(facts, "network.dns_server_count")
        if servers is not None:
            return ("PASS" if servers == 0 else "FAIL"), f"구성된 DNS name server: {servers}개"
    return "REVIEW", f"{definition.review_requirement}: 현재 REST projection으로 확정 불가"


def _evaluate(
    definition: NetworkControlDefinition,
    facts: Mapping[str, JsonValue],
    profile: KisaNetworkAssessmentProfile | None,
) -> tuple[AssessmentStatus, str, str]:
    device_status, observed = _evaluate_device(definition, facts, profile)
    if device_status != "REVIEW" or profile is None:
        return device_status, observed, "DEVICE_RULE"
    supplemental_status = profile.supplemental_status(definition.control_id)
    if supplemental_status is None:
        return device_status, observed, "DEVICE_RULE"
    return supplemental_status, observed, "ORGANIZATION_INPUT"


def _expected_summary(
    definition: NetworkControlDefinition,
    profile: KisaNetworkAssessmentProfile | None,
) -> str:
    base = f"KISA 2026 p.{definition.source_pages} · {definition.safe_criterion}"
    additions: list[str] = []
    if profile is not None and definition.control_id in _CRITERIA_FIELD_BY_CONTROL:
        field_definition = _CRITERIA_FIELD_BY_CONTROL[definition.control_id]
        value = getattr(profile, field_definition.key)
        if field_definition.input_type == "integer":
            additions.append(f"선택한 조직 기준: {value}회 이하")
        else:
            application = "필수 적용" if value is True else "조직 예외 검토"
            additions.append(f"선택한 조직 기준: {application}")
    if profile is not None:
        supplemental_status = profile.supplemental_status(definition.control_id)
        if supplemental_status is not None:
            status_label = {
                "PASS": "충족",
                "FAIL": "미충족",
                "REVIEW": "확인 필요",
                "N/A": "해당 없음",
                "ERROR": "수집 오류",
            }[supplemental_status]
            additions.append(
                f"조직 보완 판정: {status_label} (장비 수집값 아님)"
            )
    return " · ".join((base, *additions))


def evaluate_kisa_network_controls(
    facts: Mapping[str, JsonValue],
    *,
    canonical_bytes: bytes,
    captured_at: datetime,
    criteria_profile: KisaNetworkAssessmentProfile | None = None,
) -> tuple[DeviceControlResult, ...]:
    """N-01~N-38을 모두 반환하고 증거가 부족하면 fail-closed로 REVIEW합니다."""

    results: list[DeviceControlResult] = []
    for definition in KISA_NETWORK_CONTROLS:
        status, observed, judgement_source = _evaluate(
            definition, facts, criteria_profile
        )
        suffix = {
            "PASS": "COMPLIANT",
            "FAIL": "NON_COMPLIANT",
            "REVIEW": "EVIDENCE_REVIEW",
            "N/A": "NOT_APPLICABLE",
            "ERROR": "COLLECTION_ERROR",
        }[status]
        evidence = EvidenceTrace.build(
            probe_id="aruba.rest-kisa-network-projection",
            probe_version="3.0.0-DRAFT",
            method_code="NETWORK_REST_FIXED_GET",
            method_summary="인증서 고정 AOS-CX REST에서 승인된 GET만 실행하고 비식별 사실로 축소합니다.",
            source_label="AOS-CX 구조화 보안 설정",
            technical_locator=f"AOS-CX v10.13 REST projection · {definition.control_id}",
            observed_summary=observed,
            collected_at=captured_at,
            collection_status="COLLECTED",
            raw_output=canonical_bytes,
            redaction_applied=True,
        )
        results.append(
            DeviceControlResult(
                control_id=definition.control_id,
                title=definition.title,
                status=status,
                result_code=(
                    f"{definition.control_id.replace('-', '_')}_{suffix}"
                    + (
                        "_ORGANIZATION_INPUT"
                        if judgement_source == "ORGANIZATION_INPUT"
                        else ""
                    )
                ),
                expected_summary=_expected_summary(definition, criteria_profile),
                observed_summary=observed,
                action_guidance=(
                    "이 판정은 장비 수집값이 아닌 조직 보완 판정 입력을 사용했습니다. "
                    "실제 조직 증적에 맞게 입력값을 검토하고 장비 확인값과 함께 관리하세요."
                    if judgement_source == "ORGANIZATION_INPUT"
                    else
                    "장비 설정을 변경하기 전에 현재 관리 접속을 보존하고, KISA 기준과 "
                    "제조사 절차에 따라 추가 증적을 확인하세요."
                    if status == "REVIEW"
                    else "현재 관리 접속을 보존한 상태에서 KISA 기준과 제조사 절차에 따라 설정을 검토하세요."
                ),
                evidence=(evidence,),
            )
        )
    return tuple(results)
