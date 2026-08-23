"""Rocky Linux 9 x86_64 전용 PyInstaller 진입점."""

from security_audit.collector.linux_cli import main
from security_audit.platforms import LinuxDistribution

if __name__ == "__main__":
    raise SystemExit(main(forced_distribution=LinuxDistribution.ROCKY_9))
