"""KISA 2026 UNIX 서버 U-01~U-67 DRAFT 판정과 증적 계보."""

from __future__ import annotations

import re
import shlex
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from security_audit.common.canonical_json import JsonValue

from .contracts import AssessmentStatus, DeviceControlResult, EvidenceTrace
from .linux_adapters import (
    LinuxDistribution,
    linux_adapter_for,
    linux_distribution_is_debian_family,
)


@dataclass(frozen=True, slots=True)
class KisaUnixControl:
    control_id: str
    severity: str
    category: str
    title: str
    page_start: int
    page_end: int


@dataclass(frozen=True, slots=True)
class KisaUnixAssessmentProfile:
    """KISA 판단 기준 중 수치와 조직 선택이 필요한 기본값."""

    password_maximum_age_days: int = 90
    password_minimum_length: int = 8
    account_lock_threshold: int = 10
    session_timeout_seconds: int = 600
    approved_admin_accounts: tuple[str, ...] = ("root", "secai-lab")
    approved_listening_ports: tuple[int, ...] = (22,)
    approved_suid_paths: tuple[str, ...] = ()

    @classmethod
    def from_values(cls, values: Mapping[str, object] | None) -> KisaUnixAssessmentProfile:
        """화면 입력을 실행 코드가 없는 Linux 기준값으로 제한합니다."""

        if values is None:
            return cls()
        allowed = {
            "password_maximum_age_days",
            "password_minimum_length",
            "account_lock_threshold",
            "session_timeout_seconds",
            "approved_admin_accounts",
            "approved_listening_ports",
            "approved_suid_paths",
        }
        if set(values) != allowed:
            raise ValueError("LINUX_CRITERIA_KEYS_INVALID")

        def integer(key: str, minimum: int, maximum: int) -> int:
            value = values.get(key)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError("LINUX_CRITERIA_VALUE_INVALID")
            if not minimum <= value <= maximum:
                raise ValueError("LINUX_CRITERIA_VALUE_INVALID")
            return value

        def names(key: str, *, paths: bool = False) -> tuple[str, ...]:
            value = values.get(key)
            if not isinstance(value, list) or len(value) > 50:
                raise ValueError("LINUX_CRITERIA_VALUE_INVALID")
            normalized: list[str] = []
            pattern = r"/[A-Za-z0-9._/+:-]+" if paths else r"[A-Za-z0-9._-]+"
            for item in value:
                if (
                    not isinstance(item, str)
                    or len(item) > 160
                    or re.fullmatch(pattern, item) is None
                ):
                    raise ValueError("LINUX_CRITERIA_VALUE_INVALID")
                if item not in normalized:
                    normalized.append(item)
            return tuple(sorted(normalized, key=str.casefold))

        ports = values.get("approved_listening_ports")
        if not isinstance(ports, list) or len(ports) > 50:
            raise ValueError("LINUX_CRITERIA_VALUE_INVALID")
        normalized_ports: list[int] = []
        for port in ports:
            if (
                not isinstance(port, int)
                or isinstance(port, bool)
                or not 1 <= port <= 65_535
            ):
                raise ValueError("LINUX_CRITERIA_VALUE_INVALID")
            if port not in normalized_ports:
                normalized_ports.append(port)
        return cls(
            password_maximum_age_days=integer(
                "password_maximum_age_days", 1, 365
            ),
            password_minimum_length=integer("password_minimum_length", 8, 64),
            account_lock_threshold=integer("account_lock_threshold", 1, 20),
            session_timeout_seconds=integer("session_timeout_seconds", 60, 3_600),
            approved_admin_accounts=names("approved_admin_accounts"),
            approved_listening_ports=tuple(sorted(normalized_ports)),
            approved_suid_paths=names("approved_suid_paths", paths=True),
        )

    def public_values(self) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], {
            "password_maximum_age_days": self.password_maximum_age_days,
            "password_minimum_length": self.password_minimum_length,
            "account_lock_threshold": self.account_lock_threshold,
            "session_timeout_seconds": self.session_timeout_seconds,
            "approved_admin_accounts": list(self.approved_admin_accounts),
            "approved_listening_ports": list(self.approved_listening_ports),
            "approved_suid_paths": list(self.approved_suid_paths),
        })


_CONTROL_ROWS: tuple[tuple[int, str, str, int], ...] = (
    (1, "상", "root 계정 원격 접속 제한", 12),
    (2, "상", "비밀번호 관리정책 설정", 15),
    (3, "상", "계정 잠금 임계값 설정", 21),
    (4, "상", "비밀번호 파일 보호", 25),
    (5, "상", "root 이외의 UID가 ‘0’ 금지", 27),
    (6, "상", "사용자 계정 su 기능 제한", 29),
    (7, "하", "불필요한 계정 제거", 31),
    (8, "중", "관리자 그룹에 최소한의 계정 포함", 32),
    (9, "하", "계정이 존재하지 않는 GID 금지", 33),
    (10, "중", "동일한 UID 금지", 34),
    (11, "하", "사용자 shell 점검", 35),
    (12, "하", "세션 종료 시간 설정", 36),
    (13, "중", "안전한 비밀번호 암호화 알고리즘 사용", 37),
    (14, "상", "root 홈, 패스 디렉터리 권한 및 패스 설정", 39),
    (15, "상", "파일 및 디렉터리 소유자 설정", 40),
    (16, "상", "/etc/passwd 파일 소유자 및 권한 설정", 41),
    (17, "상", "시스템 시작 스크립트 권한 설정", 42),
    (18, "상", "/etc/shadow 파일 소유자 및 권한 설정", 44),
    (19, "상", "/etc/hosts 파일 소유자 및 권한 설정", 45),
    (20, "상", "/etc/(x)inetd.conf 파일 소유자 및 권한 설정", 46),
    (21, "상", "/etc/(r)syslog.conf 파일 소유자 및 권한 설정", 48),
    (22, "상", "/etc/services 파일 소유자 및 권한 설정", 49),
    (23, "상", "SUID, SGID, Sticky bit 설정 파일 점검", 50),
    (24, "상", "사용자, 시스템 환경변수 파일 소유자 및 권한 설정", 51),
    (25, "상", "world writable 파일 점검", 52),
    (26, "상", "/dev에 존재하지 않는 device 파일 점검", 53),
    (27, "상", "$HOME/.rhosts, hosts.equiv 사용 금지", 54),
    (28, "상", "접속 IP 및 포트 제한", 56),
    (29, "하", "hosts.lpd 파일 소유자 및 권한 설정", 61),
    (30, "중", "UMASK 설정 관리", 62),
    (31, "중", "홈디렉토리 소유자 및 권한 설정", 65),
    (32, "중", "홈 디렉토리로 지정한 디렉토리의 존재 관리", 66),
    (33, "하", "숨겨진 파일 및 디렉토리 검색 및 제거", 67),
    (34, "상", "Finger 서비스 비활성화", 68),
    (35, "상", "공유 서비스에 대한 익명 접근 제한 설정", 70),
    (36, "상", "r 계열 서비스 비활성화", 77),
    (37, "상", "crontab 설정파일 권한 설정 미흡", 80),
    (38, "상", "DoS 공격에 취약한 서비스 비활성화", 83),
    (39, "상", "불필요한 NFS 서비스 비활성화", 86),
    (40, "상", "NFS 접근 통제", 89),
    (41, "상", "불필요한 automountd 제거", 93),
    (42, "상", "불필요한 RPC 서비스 비활성화", 96),
    (43, "상", "NIS, NIS+ 점검", 99),
    (44, "상", "tftp, talk 서비스 비활성화", 102),
    (45, "상", "메일 서비스 버전 점검", 105),
    (46, "상", "일반 사용자의 메일 서비스 실행 방지", 111),
    (47, "상", "스팸 메일 릴레이 제한", 113),
    (48, "중", "expn, vrfy 명령어 제한", 116),
    (49, "상", "DNS 보안 버전 패치", 118),
    (50, "상", "DNS ZoneTransfer 설정", 121),
    (51, "중", "DNS 서비스의 취약한 동적 업데이트 설정 금지", 122),
    (52, "중", "Telnet 서비스 비활성화", 124),
    (53, "하", "FTP 서비스 정보 노출 제한", 127),
    (54, "중", "암호화되지 않는 FTP 서비스 비활성화", 131),
    (55, "중", "FTP 계정 shell 제한", 134),
    (56, "하", "FTP 서비스 접근 제어 설정", 135),
    (57, "중", "Ftpusers 파일 설정", 139),
    (58, "중", "불필요한 SNMP 서비스 구동 점검", 141),
    (59, "상", "안전한 SNMP 버전 사용", 143),
    (60, "중", "SNMP Community String 복잡성 설정", 145),
    (61, "상", "SNMP Access Control 설정", 148),
    (62, "하", "로그인 시 경고 메시지 설정", 150),
    (63, "중", "sudo 명령어 접근 관리", 159),
    (64, "상", "주기적 보안 패치 및 벤더 권고사항 적용", 160),
    (65, "중", "NTP 및 시각 동기화 설정", 164),
    (66, "중", "정책에 따른 시스템 로깅 설정", 166),
    (67, "중", "로그 디렉터리 소유자 및 권한 설정", 171),
)


def _category(number: int) -> str:
    if number <= 13:
        return "1. 계정 관리"
    if number <= 33:
        return "2. 파일 및 디렉토리 관리"
    if number <= 63:
        return "3. 서비스 관리"
    if number == 64:
        return "4. 패치 관리"
    return "5. 로그 관리"


KISA_2026_UNIX_CONTROLS = tuple(
    KisaUnixControl(
        control_id=f"U-{number:02d}",
        severity=severity,
        category=_category(number),
        title=title,
        page_start=page,
        page_end=(
            _CONTROL_ROWS[index + 1][3] - 1
            if index + 1 < len(_CONTROL_ROWS)
            else 171
        ),
    )
    for index, (number, severity, title, page) in enumerate(_CONTROL_ROWS)
)


_ACCOUNT_PROBES: dict[str, tuple[str, ...]] = {
    "U-01": ("linux.sshd-effective",),
    "U-02": ("linux.login-defs", "linux.pam-policy"),
    "U-03": ("linux.pam-policy",),
    "U-04": ("linux.passwd-db",),
    "U-05": ("linux.passwd-db",),
    "U-06": ("linux.pam-su", "linux.group-db"),
    "U-07": ("linux.passwd-db",),
    "U-08": ("linux.group-db",),
    "U-09": ("linux.passwd-db", "linux.group-db"),
    "U-10": ("linux.passwd-db",),
    "U-11": ("linux.passwd-db",),
    "U-12": ("linux.profile-policy",),
    "U-13": ("linux.login-defs", "linux.pam-policy"),
}

_FILE_PROBES: dict[str, tuple[str, ...]] = {
    "U-14": ("linux.passwd-db", "linux.profile-policy"),
    "U-15": ("linux.ownerless",),
    "U-16": ("linux.passwd-mode",),
    "U-17": ("linux.startup-unsafe",),
    "U-18": ("linux.shadow-mode",),
    "U-19": ("linux.hosts-mode",),
    "U-20": ("linux.inetd-mode",),
    "U-21": ("linux.syslog-mode",),
    "U-22": ("linux.services-mode",),
    "U-23": ("linux.suid-sgid",),
    "U-24": ("linux.environment-unsafe",),
    "U-25": ("linux.world-writable",),
    "U-26": ("linux.dev-regular",),
    "U-27": ("linux.rhosts",),
    "U-28": (
        "linux.firewall-state",
        "linux.firewall-rules",
        "linux.listening-sockets",
    ),
    "U-29": ("linux.hosts-lpd-mode",),
    "U-30": ("linux.login-defs", "linux.profile-policy"),
    "U-31": ("linux.passwd-db",),
    "U-32": ("linux.passwd-db",),
    "U-33": ("linux.home-hidden",),
}


def _probe_ids(control_id: str) -> tuple[str, ...]:
    if control_id in _ACCOUNT_PROBES:
        return _ACCOUNT_PROBES[control_id]
    if control_id in _FILE_PROBES:
        return _FILE_PROBES[control_id]
    special = {
        "U-35": (
            "linux.active-services",
            "linux.enabled-services",
            "linux.service-config",
            "linux.nfs-exports",
        ),
        "U-37": ("linux.cron-unsafe",),
        "U-40": ("linux.active-services", "linux.nfs-exports"),
        "U-45": (
            "linux.active-services",
            "linux.package-inventory",
            "linux.pending-security-updates",
        ),
        "U-49": (
            "linux.active-services",
            "linux.package-inventory",
            "linux.pending-security-updates",
        ),
        "U-57": ("linux.active-services", "linux.ftpusers"),
        "U-55": (
            "linux.active-services",
            "linux.enabled-services",
            "linux.service-config",
            "linux.passwd-db",
        ),
        "U-62": ("linux.banner",),
        "U-63": ("linux.sudoers-check", "linux.sudoers-config"),
        "U-64": ("linux.pending-security-updates",),
        "U-65": ("linux.time-sync",),
        "U-66": ("linux.logging-state", "linux.logging-config"),
        "U-67": ("linux.log-metadata",),
    }
    return special.get(
        control_id,
        (
            "linux.active-services",
            "linux.enabled-services",
            "linux.service-config",
        ),
    )


def probe_ids_for_control(control_id: str) -> tuple[str, ...]:
    """점검 항목 판정에 필요한 읽기 전용 Probe ID를 반환합니다."""

    if not any(item.control_id == control_id for item in KISA_2026_UNIX_CONTROLS):
        return ()
    return _probe_ids(control_id)


def control_ids_for_probe(probe_id: str) -> tuple[str, ...]:
    """Probe 수집 진행 상태와 연관된 U 항목을 판정 순서대로 반환합니다."""

    return tuple(
        item.control_id
        for item in KISA_2026_UNIX_CONTROLS
        if probe_id in _probe_ids(item.control_id)
    )


def _text(outputs: Mapping[str, bytes], probe_id: str) -> str:
    return outputs[probe_id].decode("utf-8", errors="replace").strip()


def _count_nonempty(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.strip())


def _passwd_rows(text: str) -> list[tuple[str, str, int, int, str, str]]:
    rows: list[tuple[str, str, int, int, str, str]] = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        try:
            rows.append(
                (parts[0], parts[1], int(parts[2]), int(parts[3]), parts[5], parts[6])
            )
        except ValueError:
            continue
    return rows


def _group_rows(text: str) -> list[tuple[str, int, tuple[str, ...]]]:
    rows: list[tuple[str, int, tuple[str, ...]]] = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 4:
            continue
        try:
            rows.append(
                (
                    parts[0],
                    int(parts[2]),
                    tuple(item for item in parts[3].split(",") if item),
                )
            )
        except ValueError:
            continue
    return rows


def _stat_is_safe(
    text: str,
    *,
    maximum_mode: int,
    allowed_groups: tuple[str, ...] = ("root",),
) -> bool | None:
    if not text:
        return None
    last = text.splitlines()[-1]
    parts = last.split(":")
    if len(parts) == 4:
        _, mode, owner, group = parts
    elif len(parts) == 3:
        mode, owner, group = parts
    else:
        return None
    try:
        return (
            int(mode, 8) <= maximum_mode
            and owner == "root"
            and group in allowed_groups
        )
    except ValueError:
        return None


def _service_present(text: str, names: tuple[str, ...]) -> bool:
    normalized = text.casefold()
    return any(name.casefold() in normalized for name in names)


def _pending_update_count(text: str, distribution: LinuxDistribution) -> int | None:
    stripped = text.strip()
    if not stripped or stripped == "0":
        return 0
    if linux_distribution_is_debian_family(distribution):
        match = re.search(r"(?m)^(\d+) upgraded,", stripped)
        if match is not None:
            return int(match.group(1))
        return len(re.findall(r"(?m)^Inst\s+", stripped)) or None
    package_lines = [
        line
        for line in stripped.splitlines()
        if line.strip()
        and not line.startswith(("Last metadata", "Obsoleting", "Security:"))
    ]
    return len(package_lines)


def _unsafe_log_metadata_count(text: str) -> int | None:
    """KISA U-67의 root 소유·644 이하 조건과 다른 로그 수를 계산합니다."""

    rows = [line for line in text.splitlines() if line.strip()]
    if not rows:
        return None
    unsafe = 0
    for row in rows:
        parts = row.split(":", maxsplit=3)
        if len(parts) != 4:
            return None
        mode, owner, _, _ = parts
        try:
            numeric_mode = int(mode, 8)
        except ValueError:
            return None
        if owner != "root" or numeric_mode > 0o644:
            unsafe += 1
    return unsafe


def _initial_assessment(
    control: KisaUnixControl,
    outputs: Mapping[str, bytes],
    distribution: LinuxDistribution,
    profile: KisaUnixAssessmentProfile,
) -> tuple[AssessmentStatus, str]:
    cid = control.control_id
    passwd = _passwd_rows(_text(outputs, "linux.passwd-db")) if cid in {
        "U-04",
        "U-05",
        "U-07",
        "U-09",
        "U-10",
        "U-11",
        "U-14",
        "U-31",
        "U-32",
        "U-55",
    } and "linux.passwd-db" in outputs else []
    groups = _group_rows(_text(outputs, "linux.group-db")) if cid in {
        "U-06",
        "U-08",
        "U-09",
    } and "linux.group-db" in outputs else []

    if cid == "U-01":
        root_login_match = re.search(
            r"(?m)^permitrootlogin\s+(\S+)$",
            _text(outputs, "linux.sshd-effective"),
        )
        if root_login_match is None:
            return "REVIEW", "SSH의 root 직접 접속 적용값을 해석하지 못했습니다."
        setting = root_login_match.group(1).casefold()
        return (
            ("PASS" if setting in {"no", "prohibit-password"} else "FAIL"),
            f"SSH root 직접 접속 설정은 {setting}입니다.",
        )
    if cid == "U-02":
        source = _text(outputs, "linux.login-defs") + "\n" + _text(
            outputs, "linux.pam-policy"
        )
        maximum = re.search(r"(?m)^PASS_MAX_DAYS\s+(\d+)", source)
        minimums = [
            int(minimum_value)
            for minimum_value in re.findall(
                r"(?:PASS_MIN_LEN\s+|minlen=)(\d+)", source
            )
        ]
        complex_policy = "pam_pwquality.so" in source
        password_policy_passed = (
            maximum is not None
            and int(maximum.group(1)) <= profile.password_maximum_age_days
            and bool(minimums)
            and max(minimums) >= profile.password_minimum_length
            and complex_policy
        )
        summary = (
            f"최대 사용 기간 {maximum.group(1) if maximum else '미확인'}일, "
            f"최소 길이 {max(minimums) if minimums else '미확인'}자, "
            f"복잡성 정책 {'확인' if complex_policy else '미확인'}"
        )
        return ("PASS" if password_policy_passed else "FAIL"), summary
    if cid == "U-03":
        match = re.search(r"\bdeny=(\d+)\b", _text(outputs, "linux.pam-policy"))
        if match is None:
            return "FAIL", "계정 잠금 임계값을 확인하지 못했습니다."
        threshold = int(match.group(1))
        lock_policy_passed = 0 < threshold <= profile.account_lock_threshold
        return (
            "PASS" if lock_policy_passed else "FAIL"
        ), f"계정 잠금 임계값은 {threshold}회입니다."
    if cid == "U-04":
        protected = bool(passwd) and all(row[1] in {"x", "*", "!"} for row in passwd)
        return (
            ("PASS" if protected else "FAIL"),
            "비밀번호 해시는 shadow 파일로 분리되어 있습니다."
            if protected
            else "passwd 파일에서 분리되지 않은 비밀번호 필드가 발견되었습니다.",
        )
    if cid == "U-05":
        uid_zero_names = [row[0] for row in passwd if row[2] == 0]
        return (
            ("PASS" if uid_zero_names == ["root"] else "FAIL"),
            f"UID 0 계정은 {len(uid_zero_names)}개입니다.",
        )
    if cid == "U-06":
        pam = _text(outputs, "linux.pam-su")
        restricted = "pam_wheel.so" in pam or "pam_group.so" in pam
        return (
            ("PASS" if restricted else "FAIL"),
            "su 사용 제한 PAM 설정을 확인했습니다."
            if restricted
            else "su 사용 제한 PAM 설정을 확인하지 못했습니다.",
        )
    if cid == "U-07":
        safe_shells = ("nologin", "false", "sync", "shutdown", "halt")
        login_accounts = {
            row[0]
            for row in passwd
            if not any(row[5].endswith(item) for item in safe_shells)
        }
        unapproved = login_accounts.difference(profile.approved_admin_accounts)
        return (
            "PASS" if not unapproved else "FAIL",
            f"로그인 가능 계정 {len(login_accounts)}개 중 기본 승인 목록 밖 계정은 "
            f"{len(unapproved)}개입니다.",
        )
    if cid == "U-08":
        admin_accounts = {"root"}
        for group_name, _gid, members in groups:
            if group_name.casefold() in {"root", "wheel", "sudo"}:
                admin_accounts.update(members)
        unapproved = admin_accounts.difference(profile.approved_admin_accounts)
        return (
            "PASS" if not unapproved else "FAIL",
            f"관리자 그룹 계정 {len(admin_accounts)}개 중 기본 승인 목록 밖 계정은 "
            f"{len(unapproved)}개입니다.",
        )
    if cid == "U-09":
        missing_gids = {row[3] for row in passwd} - {row[1] for row in groups}
        return (
            ("PASS" if not missing_gids else "FAIL"),
            f"그룹이 없는 계정 GID는 {len(missing_gids)}개입니다.",
        )
    if cid == "U-10":
        uid_counts = Counter(row[2] for row in passwd)
        duplicates = sum(uid_count - 1 for uid_count in uid_counts.values() if uid_count > 1)
        return (
            ("PASS" if duplicates == 0 else "FAIL"),
            f"중복 UID는 {duplicates}개입니다.",
        )
    if cid == "U-11":
        safe_shells = ("nologin", "false", "sync", "shutdown", "halt")
        unsafe_shell_count = sum(
            1
            for row in passwd
            if 0 < row[2] < 1000 and not any(row[5].endswith(item) for item in safe_shells)
        )
        return (
            ("PASS" if unsafe_shell_count == 0 else "FAIL"),
            f"로그인 shell이 필요한지 확인할 시스템 계정은 {unsafe_shell_count}개입니다.",
        )
    if cid == "U-12":
        tmout_values = [
            int(tmout_value)
            for tmout_value in re.findall(
                r"(?im)^\s*TMOUT\s*[= ]\s*(\d+)",
                _text(outputs, "linux.profile-policy"),
            )
        ]
        tmout_passed = (
            bool(tmout_values)
            and min(tmout_values) <= profile.session_timeout_seconds
        )
        return (
            ("PASS" if tmout_passed else "FAIL"),
            f"자동 세션 종료 시간은 {min(tmout_values) if tmout_values else '미설정'}초입니다.",
        )
    if cid == "U-13":
        source = (
            _text(outputs, "linux.login-defs")
            + "\n"
            + _text(outputs, "linux.pam-policy")
        ).casefold()
        password_hash_safe = "yescrypt" in source or "sha512" in source
        return (
            ("PASS" if password_hash_safe else "FAIL"),
            "안전한 비밀번호 해시 알고리즘 설정을 확인했습니다."
            if password_hash_safe
            else "yescrypt 또는 SHA-512 해시 설정을 확인하지 못했습니다.",
        )
    if cid == "U-14":
        root_rows = [row for row in passwd if row[0] == "root"]
        root_home = root_rows[0][4] if root_rows else "미확인"
        return "REVIEW", f"root 홈은 {root_home}이며 PATH 디렉터리 권한 확인이 필요합니다."
    if cid in {"U-15", "U-17", "U-24", "U-25", "U-26", "U-27", "U-37"}:
        probe = _probe_ids(cid)[0]
        abnormal_count = _count_nonempty(_text(outputs, probe))
        return (
            ("PASS" if abnormal_count == 0 else "FAIL"),
            f"안전 기준과 다른 대상은 {abnormal_count}개입니다.",
        )
    if cid == "U-67":
        unsafe_log_count = _unsafe_log_metadata_count(
            _text(outputs, "linux.log-metadata")
        )
        if unsafe_log_count is None:
            return "REVIEW", "로그 파일 소유자와 권한 자료를 자동으로 해석하지 못했습니다."
        return (
            ("PASS" if unsafe_log_count == 0 else "FAIL"),
            f"root 소유·644 이하 기준과 다른 로그 파일은 {unsafe_log_count}개입니다.",
        )
    if cid in {"U-16", "U-19", "U-22"}:
        probe = _probe_ids(cid)[0]
        stat_safe = _stat_is_safe(_text(outputs, probe), maximum_mode=0o644)
        return (
            "REVIEW" if stat_safe is None else ("PASS" if stat_safe else "FAIL"),
            f"파일 메타데이터 확인값은 {_text(outputs, probe) or '파일 없음'}입니다.",
        )
    if cid in {"U-18", "U-21"}:
        probe = _probe_ids(cid)[0]
        stat_safe = _stat_is_safe(
            _text(outputs, probe),
            maximum_mode=0o640,
            allowed_groups=("root", "shadow", "adm"),
        )
        return (
            "REVIEW" if stat_safe is None else ("PASS" if stat_safe else "FAIL"),
            f"파일 메타데이터 확인값은 {_text(outputs, probe) or '파일 없음'}입니다.",
        )
    if cid in {"U-20", "U-29"}:
        probe = _probe_ids(cid)[0]
        legacy_metadata = _text(outputs, probe)
        if not legacy_metadata:
            return "N/A", "해당 레거시 서비스 설정 파일이 존재하지 않습니다."
        stat_safe = _stat_is_safe(legacy_metadata, maximum_mode=0o600)
        return (
            "REVIEW" if stat_safe is None else ("PASS" if stat_safe else "FAIL"),
            f"파일 메타데이터 확인값은 {legacy_metadata}입니다.",
        )
    if cid == "U-23":
        suid_paths = {
            line.strip()
            for line in _text(outputs, "linux.suid-sgid").splitlines()
            if line.strip()
        }
        if not profile.approved_suid_paths:
            return "REVIEW", f"SUID·SGID 파일 {len(suid_paths)}개를 확인해야 합니다."
        unapproved = suid_paths.difference(profile.approved_suid_paths)
        return (
            "PASS" if not unapproved else "FAIL",
            f"SUID·SGID 파일 {len(suid_paths)}개 중 승인 목록 밖 파일은 "
            f"{len(unapproved)}개입니다.",
        )
    if cid == "U-28":
        state = _text(outputs, "linux.firewall-state").casefold()
        firewall_active = "active" in state or "running" in state
        if not firewall_active:
            return "FAIL", "호스트 방화벽이 활성 상태가 아닙니다."
        listening_ports = {
            int(value)
            for value in re.findall(
                r":(\d{1,5})(?=\s|$)",
                _text(outputs, "linux.listening-sockets"),
            )
            if 1 <= int(value) <= 65_535
        }
        unapproved_ports = listening_ports.difference(
            profile.approved_listening_ports
        )
        return (
            "PASS" if not unapproved_ports else "FAIL",
            f"수신 포트 {len(listening_ports)}개 중 기본 승인 목록 밖 포트는 "
            f"{len(unapproved_ports)}개입니다.",
        )
    if cid == "U-30":
        source = _text(outputs, "linux.login-defs") + "\n" + _text(
            outputs, "linux.profile-policy"
        )
        umask_values = re.findall(
            r"(?im)^\s*(?:UMASK|umask)\s*[= ]\s*0?([0-7]{3})", source
        )
        modes = [int(umask_value, 8) for umask_value in umask_values]
        umask_passed = bool(modes) and all(
            mode & 0o022 == 0o022 for mode in modes
        )
        return (
            ("PASS" if umask_passed else "FAIL"),
            f"확인된 UMASK는 {', '.join(umask_values) if umask_values else '미설정'}입니다.",
        )
    if cid in {"U-31", "U-32", "U-33"}:
        probe = _probe_ids(cid)[0]
        home_count = _count_nonempty(_text(outputs, probe))
        return "REVIEW", f"홈 디렉터리 관련 대상 {home_count}개를 계정 용도와 함께 확인해야 합니다."

    active_text = "\n".join(
        _text(outputs, probe)
        for probe in ("linux.active-services", "linux.enabled-services")
        if probe in outputs
    )
    config = _text(outputs, "linux.service-config") if "linux.service-config" in outputs else ""
    service_names: dict[str, tuple[str, ...]] = {
        "U-34": ("finger",),
        "U-35": ("smb", "samba", "vsftpd", "proftpd", "nfs"),
        "U-36": ("rsh", "rlogin", "rexec"),
        "U-38": ("echo", "daytime", "discard", "chargen"),
        "U-39": ("nfs-server", "nfs-kernel-server"),
        "U-40": ("nfs-server", "nfs-kernel-server"),
        "U-41": ("autofs", "automount"),
        "U-42": ("rpcbind",),
        "U-43": ("ypbind", "nis"),
        "U-44": ("tftp", "talk"),
        "U-45": ("postfix", "sendmail", "exim"),
        "U-46": ("postfix", "sendmail", "exim"),
        "U-47": ("postfix", "sendmail", "exim"),
        "U-48": ("postfix", "sendmail", "exim"),
        "U-49": ("named", "bind9"),
        "U-50": ("named", "bind9"),
        "U-51": ("named", "bind9"),
        "U-52": ("telnet",),
        "U-53": ("vsftpd", "proftpd", "pure-ftpd"),
        "U-54": ("vsftpd", "proftpd", "pure-ftpd"),
        "U-55": ("vsftpd", "proftpd", "pure-ftpd"),
        "U-56": ("vsftpd", "proftpd", "pure-ftpd"),
        "U-57": ("vsftpd", "proftpd", "pure-ftpd"),
        "U-58": ("snmpd",),
        "U-59": ("snmpd",),
        "U-60": ("snmpd",),
        "U-61": ("snmpd",),
    }
    active = _service_present(active_text, service_names.get(cid, ()))
    if cid == "U-35":
        if not active:
            return "N/A", "익명 접근 제한을 확인할 공유 서비스가 활성 상태가 아닙니다."
        nfs_exports = _text(outputs, "linux.nfs-exports")
        anonymous_access_unsafe = bool(
            re.search(
                r"(?im)^\s*(?:anonymous_?enable|guest\s+ok|public)\s*[=:]\s*(?:yes|true|1)\b",
                config,
            )
            or re.search(r"(?im)^\s*<Anonymous\b", config)
            or re.search(r"(?i)\b(?:anonuid|anongid)=", nfs_exports)
        )
        if anonymous_access_unsafe:
            return "FAIL", "공유 서비스에서 익명 또는 게스트 접근 허용 설정을 확인했습니다."
        return "REVIEW", "공유 서비스가 활성 상태이며 익명 접근 제한 설정을 추가 확인해야 합니다."
    if cid in {"U-34", "U-36", "U-38", "U-41", "U-42", "U-43", "U-44", "U-52", "U-54"}:
        return (
            ("FAIL" if active else "PASS"),
            "금지 또는 불필요 서비스가 활성 상태입니다."
            if active
            else "금지 또는 불필요 서비스가 활성 상태가 아닙니다.",
        )
    if cid in {"U-39", "U-58"}:
        return (
            ("REVIEW" if active else "PASS"),
            "서비스가 활성 상태이므로 업무상 필요 여부를 확인해야 합니다."
            if active
            else "서비스가 활성 상태가 아닙니다.",
        )
    if cid == "U-40":
        if not active:
            return "N/A", "NFS 서비스가 활성 상태가 아닙니다."
        exports = _text(outputs, "linux.nfs-exports")
        nfs_unsafe = bool(
            "no_root_squash" in exports
            or re.search(r"(?m)^\s*/\S*\s+\*", exports)
        )
        return (
            ("FAIL" if nfs_unsafe or not exports else "PASS"),
            "NFS 공유의 접근 범위와 root 권한 제한을 확인했습니다.",
        )
    if cid in {"U-45", "U-49", "U-64"}:
        if cid != "U-64" and not active:
            return "N/A", "해당 서비스가 활성 상태가 아닙니다."
        pending_update_count = _pending_update_count(
            _text(outputs, "linux.pending-security-updates"), distribution
        )
        if pending_update_count is None:
            return "REVIEW", "보안 업데이트 결과를 자동으로 해석하지 못했습니다."
        if pending_update_count > 0:
            return "FAIL", f"대기 중인 보안 업데이트는 {pending_update_count}개입니다."
        if cid in {"U-45", "U-49"}:
            return (
                "REVIEW",
                "대기 중인 보안 업데이트는 없지만 설치 버전이 최신인지 "
                "공급자 기준 확인이 필요합니다.",
            )
        return "PASS", "대기 중인 보안 업데이트는 0개입니다."
    if cid in {"U-46", "U-47", "U-53", "U-56"}:
        if not active:
            return "N/A", "해당 서비스가 활성 상태가 아닙니다."
        return "REVIEW", "서비스 설정을 업무 목적과 허용 정책에 따라 확인해야 합니다."
    if cid == "U-48":
        if not active:
            return "N/A", "메일 서비스가 활성 상태가 아닙니다."
        restricted = "noexpn" in config.casefold() and "novrfy" in config.casefold()
        return (
            ("PASS" if restricted else "FAIL"),
            "EXPN·VRFY 제한 설정을 확인했습니다."
            if restricted
            else "EXPN·VRFY 제한 설정을 확인하지 못했습니다.",
        )
    if cid == "U-50":
        if not active:
            return "N/A", "DNS 서비스가 활성 상태가 아닙니다."
        safe = "allow-transfer" in config and "none" in config.casefold()
        return (
            ("PASS" if safe else "REVIEW"),
            "Zone Transfer 제한 설정을 확인했습니다."
            if safe
            else "Zone Transfer 허용 대상을 추가 확인해야 합니다.",
        )
    if cid == "U-51":
        if not active:
            return "N/A", "DNS 서비스가 활성 상태가 아닙니다."
        safe = "allow-update" in config and "none" in config.casefold()
        return (
            ("PASS" if safe else "REVIEW"),
            "동적 업데이트 제한 설정을 확인했습니다."
            if safe
            else "동적 업데이트 허용 대상을 추가 확인해야 합니다.",
        )
    if cid == "U-55":
        if not active:
            return "N/A", "FTP 서비스가 활성 상태가 아닙니다."
        ftp_rows = [row for row in passwd if row[0] in {"ftp", "anonymous"}]
        safe = all(row[5].endswith(("nologin", "false")) for row in ftp_rows)
        return (
            ("PASS" if safe else "FAIL"),
            f"FTP 전용 계정 shell 제한 대상은 {len(ftp_rows)}개입니다.",
        )
    if cid == "U-57":
        if not active:
            return "N/A", "FTP 서비스가 활성 상태가 아닙니다."
        users = {line.strip() for line in _text(outputs, "linux.ftpusers").splitlines()}
        required = {"root", "daemon", "bin", "sys", "adm", "lp", "sync", "shutdown", "halt"}
        missing_ftp_users = required - users
        return (
            ("PASS" if not missing_ftp_users else "FAIL"),
            f"FTP 접속 차단 기본 계정 누락은 {len(missing_ftp_users)}개입니다.",
        )
    if cid == "U-59":
        if not active:
            return "N/A", "SNMP 서비스가 활성 상태가 아닙니다."
        safe = "rouser" in config.casefold() or "rwuser" in config.casefold()
        return (
            ("PASS" if safe else "FAIL"),
            "SNMPv3 사용자 기반 설정을 확인했습니다."
            if safe
            else "SNMPv3 사용자 기반 설정을 확인하지 못했습니다.",
        )
    if cid in {"U-60", "U-61"}:
        if not active:
            return "N/A", "SNMP 서비스가 활성 상태가 아닙니다."
        if re.search(r"(?i)\b(ro|rw)community\s+(public|private)\b", config):
            return "FAIL", "기본 Community String 사용이 확인되었습니다."
        return "REVIEW", "Community String 복잡성과 접근 대상을 추가 확인해야 합니다."
    if cid == "U-62":
        banner = _text(outputs, "linux.banner")
        leaks = bool(re.search(r"(?i)ubuntu|rocky|linux|kernel|\\[rmsv]", banner))
        passed = bool(banner.strip()) and not leaks
        return (
            ("PASS" if passed else "FAIL"),
            "승인 경고 문구가 설정되어 있습니다."
            if passed
            else "경고 문구가 없거나 시스템 정보가 노출됩니다.",
        )
    if cid == "U-63":
        syntax = _text(outputs, "linux.sudoers-check").casefold()
        if "parsed ok" not in syntax and "구문 분석 정상" not in syntax:
            return "FAIL", "sudoers 구문 검사가 정상 완료되지 않았습니다."
        return "REVIEW", "sudoers 구문은 정상이지만 관리자 승인 목록과 비교해야 합니다."
    if cid == "U-65":
        time_sync_value = _text(outputs, "linux.time-sync").casefold()
        return (
            ("PASS" if time_sync_value == "yes" else "FAIL"),
            f"시각 동기화 상태는 {time_sync_value or '미확인'}입니다.",
        )
    if cid == "U-66":
        active_logging = _text(outputs, "linux.logging-state").casefold() == "active"
        configured = bool(_text(outputs, "linux.logging-config"))
        return (
            ("PASS" if active_logging and configured else "FAIL"),
            "시스템 로깅 서비스와 주요 로그 정책을 확인했습니다."
            if active_logging and configured
            else "시스템 로깅 서비스 또는 주요 로그 정책이 미흡합니다.",
        )
    return "REVIEW", "점검 자료를 조직 기준과 함께 확인해야 합니다."


LIST_EVIDENCE_PROBES = frozenset(
    {
        "linux.ownerless",
        "linux.suid-sgid",
        "linux.world-writable",
        "linux.home-hidden",
        "linux.startup-unsafe",
        "linux.environment-unsafe",
        "linux.dev-regular",
        "linux.rhosts",
        "linux.listening-sockets",
        "linux.sudoers-config",
    }
)
_RETAINED_STATUSES = frozenset({"FAIL", "REVIEW"})
MAX_RETAINED_EVIDENCE_CHARS = 20_000


def _retained_value(
    *,
    probe_id: str,
    status: AssessmentStatus,
    output: bytes | None,
) -> str | None:
    """조치 대상을 특정해야 하는 항목만 정규화 목록을 남깁니다.

    개수만으로는 점검자가 조치도 오탐 판별도 할 수 없는 목록형 항목이 대상이며,
    단일 값 판정은 요약이 곧 원본이라 보존하지 않습니다.
    """

    if status not in _RETAINED_STATUSES or probe_id not in LIST_EVIDENCE_PROBES:
        return None
    if output is None:
        return None
    text = output.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    return text[:MAX_RETAINED_EVIDENCE_CHARS]


def _evidence(
    *,
    distribution: LinuxDistribution,
    probe_id: str,
    output: bytes | None,
    observed: str,
    captured_at: datetime,
    status: AssessmentStatus,
) -> EvidenceTrace:
    adapter = linux_adapter_for(distribution)
    spec = adapter.plan.command(probe_id)
    locator = shlex.join(spec.command)
    if len(locator) > 400:
        locator = f"{spec.command[0]} (SecAI 고정 인자 allowlist; {probe_id})"
    return EvidenceTrace.build(
        probe_id=probe_id,
        probe_version="1.0.0",
        method_code="LINUX_FIXED_COMMAND",
        method_summary=(
            f"{adapter.display_name} 전용 고정 읽기 명령으로 현재 설정을 확인합니다."
        ),
        source_label=f"{adapter.display_name} · {probe_id}",
        technical_locator=locator,
        observed_summary=observed,
        collected_at=captured_at,
        collection_status="COLLECTED" if output is not None else "ERROR",
        raw_output=output or b"",
        redaction_applied=True,
        normalized_value=_retained_value(
            probe_id=probe_id,
            status=status,
            output=output,
        ),
    )


def evaluate_kisa_unix(
    outputs: Mapping[str, bytes],
    *,
    captured_at: datetime,
    distribution: LinuxDistribution,
    profile: KisaUnixAssessmentProfile | None = None,
) -> tuple[DeviceControlResult, ...]:
    """KISA UNIX 67개 항목을 누락 없이 판정하고 false PASS를 금지합니다."""

    selected_profile = profile or KisaUnixAssessmentProfile()
    results: list[DeviceControlResult] = []
    for control in KISA_2026_UNIX_CONTROLS:
        probes = _probe_ids(control.control_id)
        missing = [probe for probe in probes if probe not in outputs]
        if missing:
            status: AssessmentStatus = "ERROR"
            observed = f"필수 점검 자료 {len(missing)}개를 수집하지 못했습니다."
        else:
            status, observed = _initial_assessment(
                control,
                outputs,
                distribution,
                selected_profile,
            )
        suffix = {
            "PASS": "COMPLIANT",
            "FAIL": "NON_COMPLIANT",
            "ERROR": "COLLECTION_FAILED",
            "REVIEW": "REVIEW_REQUIRED",
            "N/A": "NOT_APPLICABLE",
        }[status]
        page = (
            str(control.page_start)
            if control.page_start == control.page_end
            else f"{control.page_start}~{control.page_end}"
        )
        evidence = tuple(
            _evidence(
                distribution=distribution,
                probe_id=probe,
                output=outputs.get(probe),
                observed=observed,
                captured_at=captured_at,
                status=status,
            )
            for probe in probes
        )
        results.append(
            DeviceControlResult(
                control_id=control.control_id,
                title=control.title,
                status=status,
                result_code=f"{control.control_id.replace('-', '_')}_{suffix}",
                expected_summary=(
                    f"KISA 2026 상세가이드 {page}쪽의 {control.control_id} "
                    f"'{control.title}' 판단 기준 충족"
                ),
                observed_summary=observed,
                action_guidance=(
                    "수집 오류를 해결한 뒤 다시 점검하세요."
                    if status == "ERROR"
                    else (
                        "조직의 사용 목적·승인 목록과 함께 확인한 뒤 기준을 확정하세요."
                        if status == "REVIEW"
                        else (
                            "현재 설정을 유지하고 정기적으로 다시 확인하세요."
                            if status in {"PASS", "N/A"}
                            else (
                                "KISA 가이드의 조치 방법을 검토하고 변경 전 영향과 "
                                "복구 절차를 확인하세요."
                            )
                        )
                    )
                ),
                evidence=evidence,
            )
        )
    return tuple(results)
