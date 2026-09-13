# EvoGuard Enterprise

EvoGuard Enterprise is an agentic AI cyber defense platform prototype for SOC-style monitoring, attack simulation, live event intake, AI analysis, autonomous response execution, threat intelligence, reporting, and realtime dashboard updates.

The project is designed as an enterprise-style senior project prototype that demonstrates how an AI-powered defense platform can receive cyber events, classify attacks, enrich them with threat intelligence, choose autonomous response actions, and present the results in a live command-center dashboard.

## Public Demo

- Frontend: <https://MayedAlshehhi.github.io/EvoGuard-Enterprise>
- Backend: <https://evoguard-enterprise-backend.onrender.com>
- Repository: <https://github.com/MayedAlshehhi/EvoGuard-Enterprise>

Render free-tier services may sleep when inactive. If the frontend login is slow, open the backend link first and wait for it to wake up.

## Demo Login

Demo credentials are not stored in the repository. Create your private Admin account through environment variables before running or deploying the backend, then create instructor accounts from the Settings page.

## Main Features

- Backend-authenticated operator login.
- Live dashboard for received backend events.
- Separate simulation center for controlled testing.
- Real-style event intake through JSON, bulk JSON, and CSV.
- Realtime Socket.IO dashboard updates with polling fallback.
- AI defense score based on received events and response quality.
- Autonomous AI response playbooks and execution logs.
- Threat intelligence IOC enrichment.
- MITRE ATT&CK mapping for attack categories.
- Global attack map with live routes and incident details.
- AI assistant for risk, reports, IOC, MITRE, health, and testing questions.
- PDF report generation and email-report support.
- Device telemetry cards for CPU, memory, disk, and network usage.
- PostgreSQL-ready Render deployment blueprint.
- Docker and local development support.

## Technology Stack

Frontend:

- React
- React Leaflet
- Recharts
- Socket.IO client
- CSS3

Backend:

- Flask
- Flask-SQLAlchemy
- Flask-SocketIO
- SQLite for local development
- PostgreSQL-ready deployment
- ReportLab PDF generation
- psutil device monitoring
- scikit-learn / joblib model artifacts

## Project Structure

```text
EvoGuard-Enterprise/
  ai_engine/          AI model, labels, attack mapping, and agentic logic
  backend/            Flask API, database models, reports, realtime events
  data/               Sample CSV event data
  docs/               Roadmap, phase notes, presentation/demo artifacts
  frontend/           React dashboard
  render.yaml         Render deployment blueprint
  requirements.txt    Python dependencies
```

## Local Setup

Install backend dependencies from the project root:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Run the backend:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise\backend
..\.venv\Scripts\python.exe app.py
```

Run the frontend in a second terminal:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise\frontend
npm install
npm start
```

Open:

```text
http://localhost:3000
```

## Environment Variables

Copy the example environment file:

```powershell
copy .env.example .env
```

Important variables:

```text
EVOGUARD_SECRET_KEY=change-this-secret
EVOGUARD_DATABASE_URL=sqlite:///evoguard.db
EVOGUARD_CORS_ORIGIN=http://localhost:3000,http://127.0.0.1:3000,https://mayedalshehhi.github.io
EVOGUARD_DEFAULT_USERNAME=your-private-admin-username
EVOGUARD_DEFAULT_PASSWORD=your-private-admin-password
EVOGUARD_INGEST_API_KEY=change-this-live-ingest-key
REACT_APP_API_BASE_URL=http://127.0.0.1:5000
```

For deployed frontend builds, set:

```text
REACT_APP_API_BASE_URL=https://evoguard-enterprise-backend.onrender.com
```

## Useful API Endpoints

```text
GET  /health
POST /auth/login
GET  /dashboard_stats?source=live
GET  /attack_history?source=live
POST /ingest_event
POST /bulk_ingest_events
POST /ingest_csv
GET  /threat_intel?source=live
GET  /ioc_lookup/<indicator>
GET  /ai_responses?source=live
GET  /ai_response_playbook
GET  /realtime_status?source=live
GET  /download_report
```

## Send Test Events

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

Run a backend smoke test:

```powershell
cd C:\Users\Mayed\Documents\ZU\EvoGuard-Enterprise
.\.venv\Scripts\python.exe backend\tools\smoke_test.py
```

## Demo Flow

1. Log in with your private Admin account.
2. Show the clean live Dashboard.
3. Use Attack Map live intake to send a real-style event.
4. Show Dashboard counters, charts, map, history, and AI analysis updating.
5. Open Threat Intel and use IOC Lookup Console.
6. Show AI Response Execution Center and autonomous playbook actions.
7. Open Simulation to show testing is separated from real live events.
8. Open Reports and download an incident PDF.
9. Ask the AI assistant about latest attack, risk, IOC, MITRE, or response actions.

## Engineering Phases Completed

- Phase 1: Backend hardening and project structure.
- Phase 2: Backend-authenticated login.
- Phase 3: Database upgrade with audit/report/action logs.
- Phase 4: Real event intake.
- Phase 5: Live input testing and frontend intake workflow.
- Phase 6: Autonomous AI response execution.
- Phase 7: Realtime Socket.IO monitoring.
- Phase 8: Threat intelligence and IOC enrichment.

## Important Notes

- EvoGuard is an advanced prototype, not a production SOC platform.
- Autonomous response actions are simulated and recorded for demonstration.
- The project does not change real firewall, endpoint, or identity systems.
- Production use would require stronger authentication, managed secrets, deployment hardening, real integrations, and security review.
