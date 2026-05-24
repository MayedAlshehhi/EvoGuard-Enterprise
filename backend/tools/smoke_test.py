import json
import urllib.request


BASE_URL = "http://127.0.0.1:5000"


def request_json(path, method="GET", payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )

    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status, json.loads(response.read().decode("utf-8"))


def main():
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
