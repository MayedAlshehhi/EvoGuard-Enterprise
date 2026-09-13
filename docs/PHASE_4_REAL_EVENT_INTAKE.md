# Phase 4 - Real Event Intake

## Goal

Phase 4 makes EvoGuard able to receive real-style cybersecurity events from external tools, scripts, CSV files, or future sensors.

## What Changed

- `/ingest_event`, `/bulk_ingest_events`, and `/ingest_csv` now accept either:
  - a logged-in browser session, or
  - an ingest API key through `X-EvoGuard-Ingest-Key` or `Authorization: Bearer <key>`.
- Live events now validate:
  - source IP address
  - destination port
  - protocol
  - attack type
  - source country
  - activity description
- Live event records now store:
  - sensor name
  - target asset
  - protocol
  - destination port
  - raw JSON payload
- The Attack Map live intake form now sends richer sensor-style event data.
- Helper scripts now support `EVOGUARD_INGEST_API_KEY`.
- The sample CSV now includes sensor and asset metadata.

## API Key Setup

Local development:

```env
EVOGUARD_INGEST_API_KEY=change-this-live-ingest-key
```

PowerShell example:

```powershell
$env:EVOGUARD_INGEST_API_KEY="change-this-live-ingest-key"
python backend/tools/send_live_event.py --type dos --count 3 --api-key $env:EVOGUARD_INGEST_API_KEY
```

CSV example:

```powershell
python backend/tools/send_csv_events.py data/sample_live_events.csv --api-key $env:EVOGUARD_INGEST_API_KEY
```

## Live Event JSON Example

```json
{
  "attack_type": "probe",
  "country": "China",
  "ip": "198.51.100.23",
  "sensor_name": "Perimeter Scanner",
  "target_asset": "Perimeter Firewall",
  "network_protocol": "tcp",
  "destination_port": 22,
  "source_activity": "Repeated port scanning across exposed services"
}
```

## Why This Matters

This separates EvoGuard from a pure simulation dashboard. The system can now receive structured live events from external senders, validate them, store them as database evidence, enrich them with AI/threat intelligence, and update the live dashboard.
