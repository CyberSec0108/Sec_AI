"""PyInstaller entry point for the Sec_AI Linux one-shot Collector."""

from security_audit.collector.linux_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
