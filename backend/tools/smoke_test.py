import json
import os
import http.cookiejar
import urllib.request


BASE_URL = "http://127.0.0.1:5000"
COOKIE_JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(COOKIE_JAR))


def request_json(path, method="GET", payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )

    with OPENER.open(request, timeout=20) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def main():
    username = os.getenv("EVOGUARD_SMOKE_USERNAME") or os.getenv("EVOGUARD_DEFAULT_USERNAME")
    password = os.getenv("EVOGUARD_SMOKE_PASSWORD") or os.getenv("EVOGUARD_DEFAULT_PASSWORD")

    if not username or not password:
        print("[ERROR] Set EVOGUARD_SMOKE_USERNAME and EVOGUARD_SMOKE_PASSWORD before running the smoke test.")
        return 1

    status, payload = request_json(
        "/auth/login",
        "POST",
        {"username": username, "password": password},
    )

    if status != 200 or not payload.get("authenticated"):
        print(f"[ERROR] Login failed: HTTP {status} {payload}")
        return 1

    print(f"[OK] Login: HTTP {status} user={payload.get('user', {}).get('username')}")

    checks = [
        ("Backend home", lambda: request_json("/")),
        ("Realtime status", lambda: request_json("/realtime_status")),
        ("Dashboard stats", lambda: request_json("/dashboard_stats?source=live")),
        ("Threat intel", lambda: request_json("/threat_intel?source=live")),
        ("AI responses", lambda: request_json("/ai_responses?source=live")),
        ("Assistant", lambda: request_json("/assistant/command", "POST", {"command": "summary"})),
    ]

    for label, fn in checks:
        status, payload = fn()
        print(f"[OK] {label}: HTTP {status}")
        if payload.get("status") == "error":
            print(payload)
            return 1

    event_status, event_payload = request_json("/test_live_event/dos", "POST")
    print(
        "[OK] Test live event: "
        f"HTTP {event_status} {event_payload.get('attack_category')} "
        f"{event_payload.get('risk_level')}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
