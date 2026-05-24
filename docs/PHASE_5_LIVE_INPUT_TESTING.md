# Phase 5 - Live Input Testing

Phase 5 adds a clean way to test EvoGuard with real-style backend events.
Simulation events stay in the Simulation page. Live events go into the real Dashboard and Attack Map.

## What Live Events Update

- Dashboard totals
- AI Defense Score
- Attack Distribution
- Weekly Attack Trend
- Global Attack Map
- Threat Intel
- Reports summary
- Recent Attack History

## Frontend Test Flow

1. Start the backend.
2. Start the React frontend.
3. Open EvoGuard and go to Attack Map.
4. Use the Phase 5 Live Intake panel.
5. Choose an attack type, country, IP, and activity.
6. Click Send Live Event.
7. Return to Dashboard to see the live event reflected there.

## Backend Endpoints

Live intake:

```txt
POST http://127.0.0.1:5000/ingest_event
```

Quick generated test event:

```txt
POST http://127.0.0.1:5000/test_live_event/dos
POST http://127.0.0.1:5000/test_live_event/probe
POST http://127.0.0.1:5000/test_live_event/r2l
POST http://127.0.0.1:5000/test_live_event/u2r
POST http://127.0.0.1:5000/test_live_event/normal
```

Examples endpoint:

```txt
GET http://127.0.0.1:5000/live_event_examples
```

Clear only live events:

```txt
POST http://127.0.0.1:5000/reset_attack_history?source=live&confirm=RESET
```

## PowerShell Example

```powershell
Invoke-RestMethod `
  -Method POST `
  -Uri "http://127.0.0.1:5000/ingest_event" `
  -ContentType "application/json" `
  -Body '{"attack_type":"dos","country":"Russia","ip":"203.0.113.77","source_activity":"High-volume TCP flood targeting public service"}'
```

## Python Tool Example

```powershell
python backend/tools/send_live_event.py --type dos --count 1
python backend/tools/send_live_event.py --type random --count 5 --interval 1.5
```

## Demo Message

EvoGuard separates real monitoring from simulation. The Dashboard and Attack Map now represent received backend events, while the Simulation page is a testing lab. The AI classifies the event, assigns risk, generates autonomous actions, updates analytics, and stores the incident.
