import argparse
import json
import random
import time
import urllib.error
import urllib.request


EVENTS = {
    "dos": [
        {"attack_label": "ddos", "country": "Russia", "source_activity": "High-volume TCP flood targeting public service"},
        {"attack_label": "tcp flood", "country": "Brazil", "source_activity": "Botnet traffic spike against protected endpoint"},
    ],
    "probe": [
        {"attack_label": "probe scan", "country": "China", "source_activity": "Repeated port scanning across exposed services"},
        {"attack_label": "nmap", "country": "India", "source_activity": "Reconnaissance scan detected on perimeter services"},
    ],
    "r2l": [
        {"attack_label": "credential attack", "country": "Germany", "source_activity": "Repeated suspicious login attempts"},
        {"attack_label": "r2l", "country": "USA", "source_activity": "Unauthorized remote access behavior detected"},
    ],
    "u2r": [
        {"attack_label": "privilege escalation", "country": "Iran", "source_activity": "Possible privilege escalation sequence"},
        {"attack_label": "rootkit", "country": "North Korea", "source_activity": "Root-level behavior observed on monitored host"},
    ],
    "normal": [
        {"attack_label": "normal", "country": "UAE", "source_activity": "Normal baseline network traffic"},
    ],
}


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def build_payload(event_type):
    event = random.choice(EVENTS[event_type]).copy()
    event["ip"] = random_ip()
    return event


def post_event(url, payload):
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Send live events into EvoGuard.")
    parser.add_argument(
        "--type",
        choices=["dos", "probe", "r2l", "u2r", "normal", "random"],
        default="random",
        help="Type of live event to send.",
    )
    parser.add_argument("--count", type=int, default=1, help="Number of events to send.")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between events.")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000/ingest_event",
        help="EvoGuard live intake URL.",
    )
    args = parser.parse_args()

    event_types = [key for key in EVENTS.keys()]

    for index in range(args.count):
        event_type = random.choice(event_types) if args.type == "random" else args.type
        payload = build_payload(event_type)

        try:
            result = post_event(args.url, payload)
        except urllib.error.URLError as error:
            print(f"[ERROR] Could not reach EvoGuard backend: {error}")
            return 1

        print(
            f"[LIVE] {index + 1}/{args.count} "
            f"{result.get('attack_category')} from {result.get('country')} "
            f"risk={result.get('risk_level')} score={result.get('risk_score')}/100"
        )

        if index < args.count - 1:
            time.sleep(args.interval)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())