from __future__ import annotations

import http.client


def main() -> int:
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=2)
    try:
        connection.request("GET", "/health/live")
        response = connection.getresponse()
        response.read()
        return 0 if response.status == 200 else 1
    except OSError:
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
