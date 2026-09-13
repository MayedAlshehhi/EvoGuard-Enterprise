import argparse
import json
import os
import urllib.error
import urllib.request


def post_csv(url, csv_path, api_key=None):
    with open(csv_path, "r", encoding="utf-8") as file:
        payload = {"csv": file.read()}

    headers = {"Content-Type": "application/json"}

    if api_key:
        headers["X-EvoGuard-Ingest-Key"] = api_key

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description="Send CSV live events into EvoGuard.")
    parser.add_argument("csv_path", help="Path to a CSV file of live events.")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000/ingest_csv",
        help="EvoGuard CSV intake URL.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("EVOGUARD_INGEST_API_KEY"),
        help="Optional EvoGuard ingest API key.",
    )
    args = parser.parse_args()

    try:
        result = post_csv(args.url, args.csv_path, args.api_key)
    except urllib.error.URLError as error:
        print(f"[ERROR] Could not reach EvoGuard backend: {error}")
        return 1

    print(
        f"[CSV] status={result.get('status')} "
        f"created={result.get('created')} endpoint={args.url}"
    )

    for event in result.get("events", [])[:10]:
        print(
            f" - {event.get('attack_category')} from {event.get('country')} "
            f"risk={event.get('risk_level')} score={event.get('risk_score')}/100 "
            f"intel={event.get('threat_intel', {}).get('reputation')}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
