"""지원 Linux 계열의 KISA UNIX 읽기 전용 수집 계획."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .contracts import PlatformContractError
from .readonly_plan import ReadOnlyCommand, ReadOnlyCommandPlan


class LinuxDistribution(StrEnum):
    """현재 제품에서 명시적으로 지원하는 Linux 배포판."""

    UBUNTU_22_04 = "UBUNTU_22_04"
    UBUNTU_24_04 = "UBUNTU_24_04"
    DEBIAN_12 = "DEBIAN_12"
    ROCKY_9 = "ROCKY_9"
    RHEL_9 = "RHEL_9"
    ALMALINUX_9 = "ALMALINUX_9"


@dataclass(frozen=True, slots=True)
class LinuxAdapter:
    distribution: LinuxDistribution
    display_name: str
    vendor: str
    plan: ReadOnlyCommandPlan


def _command(
    command_id: str,
    command: tuple[str, ...],
    *,
    root: bool = True,
    limit: int = 131_072,
    accepted: tuple[int, ...] = (0,),
    timeout: int = 30,
) -> ReadOnlyCommand:
    return ReadOnlyCommand(
        command_id,
        command,
        "ROOT" if root else "STANDARD_USER",
        timeout,
        limit,
        accepted,
    )


def _common_commands() -> tuple[ReadOnlyCommand, ...]:
    return (
        _command(
            "linux.os-release",
            ("/usr/bin/cat", "/etc/os-release"),
            root=False,
            limit=8_192,
        ),
        _command(
            "linux.passwd-db",
            ("/usr/bin/getent", "passwd"),
            limit=262_144,
        ),
        _command(
            "linux.group-db",
            ("/usr/bin/getent", "group"),
            limit=262_144,
        ),
        _command(
            "linux.login-defs",
            ("/usr/bin/cat", "/etc/login.defs"),
            limit=65_536,
        ),
        _command(
            "linux.pam-su",
            ("/usr/bin/cat", "/etc/pam.d/su"),
            limit=65_536,
            accepted=(0, 1),
        ),
        _command(
            "linux.sshd-effective",
            ("/usr/sbin/sshd", "-T"),
            limit=262_144,
        ),
        _command(
            "linux.passwd-mode",
            ("/usr/bin/stat", "-Lc", "%a:%U:%G", "/etc/passwd"),
            limit=4_096,
        ),
        _command(
            "linux.shadow-mode",
            ("/usr/bin/stat", "-Lc", "%a:%U:%G", "/etc/shadow"),
            limit=4_096,
        ),
        _command(
            "linux.hosts-mode",
            ("/usr/bin/stat", "-Lc", "%a:%U:%G", "/etc/hosts"),
            limit=4_096,
        ),
        _command(
            "linux.inetd-mode",
            (
                "/usr/bin/stat",
                "-Lc",
                "%n:%a:%U:%G",
                "/etc/inetd.conf",
                "/etc/xinetd.conf",
            ),
            limit=8_192,
            accepted=(0, 1),
        ),
        _command(
            "linux.services-mode",
            ("/usr/bin/stat", "-Lc", "%a:%U:%G", "/etc/services"),
            limit=4_096,
        ),
        _command(
            "linux.hosts-lpd-mode",
            ("/usr/bin/stat", "-Lc", "%a:%U:%G", "/etc/hosts.lpd"),
            limit=4_096,
            accepted=(0, 1),
        ),
        _command(
            "linux.startup-unsafe",
            (
                "/usr/bin/find",
                "/etc/systemd/system",
                "/etc/init.d",
                "-xdev",
                "-type",
                "f",
                "-perm",
                "/022",
                "-print",
            ),
            limit=262_144,
            accepted=(0, 1),
        ),
        _command(
            "linux.ownerless",
            (
                "/usr/bin/find",
                "/etc",
                "/usr",
                "/var",
                "-xdev",
                "(",
                "-nouser",
                "-o",
                "-nogroup",
                ")",
                "-print",
            ),
            limit=524_288,
            accepted=(0, 1),
            # 파일마다 사용자·그룹 이름 조회가 일어나 단순 순회보다 6배 느립니다.
            timeout=150,
        ),
        _command(
            "linux.suid-sgid",
            (
                "/usr/bin/find",
                "/usr",
                "/bin",
                "/sbin",
                "-xdev",
                "-type",
                "f",
                "-perm",
                "/6000",
                "-print",
            ),
            limit=524_288,
            accepted=(0, 1),
            timeout=60,
        ),
        _command(
            "linux.world-writable",
            (
                "/usr/bin/find",
                "/etc",
                "/usr",
                "/var",
                "-xdev",
                "-type",
                "f",
                "-perm",
                "-0002",
                "-print",
            ),
            limit=524_288,
            accepted=(0, 1),
            timeout=60,
        ),
        _command(
            "linux.dev-regular",
            ("/usr/bin/find", "/dev", "-xdev", "-type", "f", "-print"),
            limit=262_144,
            accepted=(0, 1),
        ),
        _command(
            "linux.rhosts",
            (
                "/usr/bin/find",
                "/root",
                "/home",
                "-xdev",
                "-name",
                ".rhosts",
                "-print",
            ),
            limit=262_144,
            accepted=(0, 1),
        ),
        _command(
            "linux.environment-unsafe",
            (
                "/usr/bin/find",
                "/etc/profile.d",
                "/root",
                "/home",
                "-xdev",
                "-type",
                "f",
                "-perm",
                "/022",
                "-print",
            ),
            limit=524_288,
            accepted=(0, 1),
        ),
        _command(
            "linux.home-hidden",
            (
                "/usr/bin/find",
                "/root",
                "/home",
                "-xdev",
                "-name",
                ".*",
                "-print",
            ),
            limit=524_288,
            accepted=(0, 1),
        ),
        _command(
            "linux.active-services",
            (
                "/usr/bin/systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
                "--plain",
            ),
            limit=524_288,
        ),
        _command(
            "linux.enabled-services",
            (
                "/usr/bin/systemctl",
                "list-unit-files",
                "--type=service",
                "--state=enabled",
                "--no-legend",
                "--no-pager",
            ),
            limit=524_288,
        ),
        _command(
            "linux.listening-sockets",
            ("/usr/bin/ss", "-lntupH"),
            limit=524_288,
            accepted=(0, 1),
        ),
        _command(
            "linux.cron-unsafe",
            (
                "/usr/bin/find",
                "/etc/cron.d",
                "/etc/cron.daily",
                "/etc/cron.hourly",
                "/etc/cron.monthly",
                "/etc/cron.weekly",
                "-xdev",
                "-type",
                "f",
                "-perm",
                "/022",
                "-print",
            ),
            limit=262_144,
            accepted=(0, 1),
        ),
        _command(
            "linux.nfs-exports",
            ("/usr/bin/cat", "/etc/exports"),
            limit=131_072,
            accepted=(0, 1),
        ),
        _command(
            "linux.ftpusers",
            (
                "/usr/bin/cat",
                "/etc/ftpusers",
                "/etc/vsftpd/ftpusers",
                "/etc/vsftpd/user_list",
            ),
            limit=65_536,
            accepted=(0, 1),
        ),
        _command(
            "linux.service-config",
            (
                "/usr/bin/grep",
                "-RhiE",
                "anonymous|no_?anonymous|guest[[:space:]]+ok|map[[:space:]]+to[[:space:]]+guest|public|allow-transfer|allow-update|relay|noexpn|novrfy|rocommunity|rwcommunity|rouser|rwuser",
                "/etc/vsftpd.conf",
                "/etc/vsftpd",
                "/etc/postfix",
                "/etc/mail",
                "/etc/bind",
                "/etc/named.conf",
                "/etc/snmp",
            ),
            limit=524_288,
            accepted=(0, 1, 2),
        ),
        _command(
            "linux.banner",
            ("/usr/bin/cat", "/etc/issue", "/etc/issue.net"),
            limit=32_768,
            accepted=(0, 1),
        ),
        _command(
            "linux.sudoers-check",
            ("/usr/sbin/visudo", "-c"),
            limit=65_536,
            accepted=(0, 1),
        ),
        _command(
            "linux.sudoers-config",
            (
                "/usr/bin/grep",
                "-RhE",
                "^[[:space:]]*[^#].*(ALL|NOPASSWD)",
                "/etc/sudoers",
                "/etc/sudoers.d",
            ),
            limit=262_144,
            accepted=(0, 1, 2),
        ),
        _command(
            "linux.time-sync",
            (
                "/usr/bin/timedatectl",
                "show",
                "--property=NTPSynchronized",
                "--value",
            ),
            root=False,
            limit=4_096,
        ),
        _command(
            "linux.auditd-state",
            ("/usr/bin/systemctl", "is-active", "auditd"),
            limit=4_096,
            accepted=(0, 3, 4),
        ),
        _command(
            "linux.logging-state",
            ("/usr/bin/systemctl", "is-active", "rsyslog"),
            limit=4_096,
            accepted=(0, 3, 4),
        ),
        _command(
            "linux.logging-config",
            (
                "/usr/bin/grep",
                "-RhE",
                "^[[:space:]]*[^#].*(auth|authpriv|daemon|kern|syslog|messages|secure)",
                "/etc/rsyslog.conf",
                "/etc/rsyslog.d",
            ),
            limit=262_144,
            accepted=(0, 1, 2),
        ),
        _command(
            "linux.log-metadata",
            (
                "/usr/bin/find",
                "/var/log",
                "-xdev",
                "-type",
                "f",
                "-printf",
                "%m:%u:%g:%p\\n",
            ),
            limit=524_288,
            accepted=(0, 1),
        ),
    )


UBUNTU_24_04 = LinuxAdapter(
    distribution=LinuxDistribution.UBUNTU_24_04,
    display_name="Ubuntu Server 24.04 LTS",
    vendor="Canonical",
    plan=ReadOnlyCommandPlan(
        platform="LINUX",
        commands=_common_commands()
        + (
            _command(
                "linux.profile-policy",
                (
                    "/usr/bin/grep",
                    "-hE",
                    "^[[:space:]]*(TMOUT|umask|UMASK)[=[:space:]]",
                    "/etc/profile",
                    "/etc/bash.bashrc",
                ),
                limit=65_536,
                accepted=(0, 1),
            ),
            _command(
                "linux.pam-policy",
                (
                    "/usr/bin/grep",
                    "-hE",
                    "pam_(faillock|tally2|pwquality|pwhistory|unix)\\.so|remember=|minlen=|deny=",
                    "/etc/pam.d/common-auth",
                    "/etc/pam.d/common-account",
                    "/etc/pam.d/common-password",
                ),
                limit=131_072,
                accepted=(0, 1),
            ),
            _command(
                "linux.syslog-mode",
                (
                    "/usr/bin/stat",
                    "-Lc",
                    "%n:%a:%U:%G",
                    "/etc/rsyslog.conf",
                ),
                limit=8_192,
                accepted=(0, 1),
            ),
            _command(
                "linux.firewall-state",
                ("/usr/sbin/ufw", "status"),
                limit=131_072,
                accepted=(0, 1),
            ),
            _command(
                "linux.firewall-rules",
                ("/usr/sbin/ufw", "status", "numbered"),
                limit=262_144,
                accepted=(0, 1),
            ),
            _command(
                "linux.package-inventory",
                ("/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\n"),
                root=False,
                limit=1_048_576,
            ),
            _command(
                "linux.pending-security-updates",
                ("/usr/bin/apt-get", "-s", "upgrade"),
                limit=1_048_576,
                accepted=(0, 100),
            ),
        ),
    ),
)


ROCKY_9 = LinuxAdapter(
    distribution=LinuxDistribution.ROCKY_9,
    display_name="Rocky Linux 9",
    vendor="Rocky Enterprise Software Foundation",
    plan=ReadOnlyCommandPlan(
        platform="LINUX",
        commands=_common_commands()
        + (
            _command(
                "linux.profile-policy",
                (
                    "/usr/bin/grep",
                    "-hE",
                    "^[[:space:]]*(TMOUT|umask|UMASK)[=[:space:]]",
                    "/etc/profile",
                    "/etc/bashrc",
                ),
                limit=65_536,
                accepted=(0, 1),
            ),
            _command(
                "linux.pam-policy",
                (
                    "/usr/bin/grep",
                    "-hE",
                    "pam_(faillock|pwquality|pwhistory|unix)\\.so|remember=|minlen=|deny=",
                    "/etc/pam.d/system-auth",
                    "/etc/pam.d/password-auth",
                ),
                limit=131_072,
                accepted=(0, 1),
            ),
            _command(
                "linux.syslog-mode",
                (
                    "/usr/bin/stat",
                    "-Lc",
                    "%n:%a:%U:%G",
                    "/etc/rsyslog.conf",
                ),
                limit=8_192,
                accepted=(0, 1),
            ),
            _command(
                "linux.firewall-state",
                ("/usr/bin/firewall-cmd", "--state"),
                limit=4_096,
                accepted=(0, 252),
            ),
            _command(
                "linux.firewall-rules",
                ("/usr/bin/firewall-cmd", "--list-all"),
                limit=262_144,
                accepted=(0, 252),
            ),
            _command(
                "linux.package-inventory",
                ("/usr/bin/rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"),
                root=False,
                limit=1_048_576,
            ),
            _command(
                "linux.pending-security-updates",
                (
                    "/usr/bin/dnf",
                    "-q",
                    "--cacheonly",
                    "check-update",
                    "--security",
                ),
                limit=1_048_576,
                accepted=(0, 100),
            ),
        ),
    ),
)


# 같은 계열의 고정 명령 계획을 재사용하되 배포판 식별과 지원 상태는 Catalog에서
# 별도로 기록합니다. 명령이나 출력 형식이 달라지는 후속 버전은 새 계획으로 분리합니다.
UBUNTU_22_04 = LinuxAdapter(
    distribution=LinuxDistribution.UBUNTU_22_04,
    display_name="Ubuntu Server 22.04 LTS",
    vendor="Canonical",
    plan=UBUNTU_24_04.plan,
)

DEBIAN_12 = LinuxAdapter(
    distribution=LinuxDistribution.DEBIAN_12,
    display_name="Debian 12",
    vendor="Debian Project",
    plan=UBUNTU_24_04.plan,
)

RHEL_9 = LinuxAdapter(
    distribution=LinuxDistribution.RHEL_9,
    display_name="Red Hat Enterprise Linux 9",
    vendor="Red Hat",
    plan=ROCKY_9.plan,
)

ALMALINUX_9 = LinuxAdapter(
    distribution=LinuxDistribution.ALMALINUX_9,
    display_name="AlmaLinux 9",
    vendor="AlmaLinux OS Foundation",
    plan=ROCKY_9.plan,
)


_ADAPTERS = {
    LinuxDistribution.UBUNTU_22_04: UBUNTU_22_04,
    LinuxDistribution.UBUNTU_24_04: UBUNTU_24_04,
    LinuxDistribution.DEBIAN_12: DEBIAN_12,
    LinuxDistribution.ROCKY_9: ROCKY_9,
    LinuxDistribution.RHEL_9: RHEL_9,
    LinuxDistribution.ALMALINUX_9: ALMALINUX_9,
}

_DEBIAN_FAMILY = frozenset(
    {
        LinuxDistribution.UBUNTU_22_04,
        LinuxDistribution.UBUNTU_24_04,
        LinuxDistribution.DEBIAN_12,
    }
)


def _os_release_value(text: str, name: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(name)}=(?:\"([^\"]+)\"|([^\n]+))$", text)
    if match is None:
        return None
    return (match.group(1) or match.group(2)).strip()


def detect_linux_distribution(os_release: bytes) -> LinuxDistribution:
    """`/etc/os-release`를 기준으로 지원 배포판을 fail-closed 탐지합니다."""

    text = os_release.decode("utf-8", errors="replace")
    distro_id = (_os_release_value(text, "ID") or "").casefold()
    version = _os_release_value(text, "VERSION_ID") or ""
    if distro_id == "ubuntu" and (
        version == "22.04" or version.startswith("22.04.")
    ):
        return LinuxDistribution.UBUNTU_22_04
    if distro_id == "ubuntu" and (
        version == "24.04" or version.startswith("24.04.")
    ):
        return LinuxDistribution.UBUNTU_24_04
    if distro_id == "debian" and (version == "12" or version.startswith("12.")):
        return LinuxDistribution.DEBIAN_12
    if distro_id == "rocky" and version.split(".", maxsplit=1)[0] == "9":
        return LinuxDistribution.ROCKY_9
    if distro_id == "rhel" and version.split(".", maxsplit=1)[0] == "9":
        return LinuxDistribution.RHEL_9
    if distro_id == "almalinux" and version.split(".", maxsplit=1)[0] == "9":
        return LinuxDistribution.ALMALINUX_9
    raise ValueError("지원하지 않는 Linux 배포판 또는 버전입니다.")


def linux_distribution_is_debian_family(
    distribution: LinuxDistribution | str,
) -> bool:
    """패키지·PAM·방화벽 출력 해석에 Debian 계열 여부를 제공합니다."""

    return LinuxDistribution(distribution) in _DEBIAN_FAMILY


def linux_adapter_for(
    distribution: LinuxDistribution | str,
) -> LinuxAdapter:
    try:
        normalized = LinuxDistribution(distribution)
        return _ADAPTERS[normalized]
    except (KeyError, ValueError) as exc:
        raise PlatformContractError("지원하지 않는 Linux 배포판입니다.") from exc
