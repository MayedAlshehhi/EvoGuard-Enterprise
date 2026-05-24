# EvoGuard Engineering Status

This document tracks the engineering work completed before the final presentation phase.

## Completed

- Backend-backed login with a seeded operator account.
- Live event intake through `/ingest_event`.
- Bulk JSON intake through `/bulk_ingest_events`.
- CSV event intake through `/ingest_csv`.
- Realtime Socket.IO dashboard updates.
- Autonomous AI response execution logs.
- AI Defense Score based on received attacks and response quality.
- Local IOC database and threat-intel enrichment.
- MITRE ATT&CK mapping for attack categories.
- Enriched PDF reports with incidents, AI actions, IOC context, and MITRE mapping.
- AI assistant command endpoint for latest attack, risk, MITRE, IOC, reports, testing, and health.
- Docker files and environment example.
- CLI tools for sending live events, CSV events, and smoke testing.

## Presentation Deferred

The final presentation deck, screenshots, architecture diagram polish, and demo script are intentionally left for the end.

## Practical Commands

Install backend dependencies:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run backend:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise\backend
..\.venv\Scripts\python.exe app.py
```

Run frontend:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise\frontend
npm start
```

Send random live events:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise
.\.venv\Scripts\python.exe backend\tools\send_live_event.py --type random --count 5 --interval 1
```

Send CSV events:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise
.\.venv\Scripts\python.exe backend\tools\send_csv_events.py data\sample_live_events.csv
```

Run Docker:

```powershell
copy .env.example .env
docker compose up --build
```
