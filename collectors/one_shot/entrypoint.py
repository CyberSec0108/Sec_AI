"""PyInstaller entry point for the Sec_AI Windows Collector."""

from security_audit.collector.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
