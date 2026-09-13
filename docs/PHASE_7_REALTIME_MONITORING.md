# Realtime Monitoring

This phase adds Socket.IO realtime updates between the Flask backend and React dashboard. The live dashboard now receives backend events immediately, while still keeping a polling fallback if WebSocket transport is unavailable.

## What changed

- Backend now supports Flask-SocketIO.
- Frontend now connects with `socket.io-client`.
- Live events pushed through `/ingest_event` broadcast immediately to the dashboard.
- AI response execution logs broadcast immediately after the backend creates them.
- Threat intelligence, audit logs, report events, and reset actions broadcast to connected clients.
- Dashboard header shows `Connecting...`, `Realtime Connected`, or `Polling Fallback`.
- Backend tracks active Socket.IO clients and includes `connected_clients` in realtime status and heartbeat payloads.
- The dashboard status pill tooltip shows last heartbeat time, transport mode, and connected client count.
- If sockets are unavailable, the frontend keeps using the existing polling fallback.

## Backend events

- `evoguard:connected` sends initial live stats, history, AI response logs, threat intel, and realtime status.
- `evoguard:heartbeat` confirms the socket connection is still alive.
- `evoguard:new_attack` sends each new live or simulation attack event with refreshed stats and threat intel.
- `evoguard:ai_response` sends autonomous AI response execution logs.
- `evoguard:stats_updated` sends refreshed dashboard statistics.
- `evoguard:threat_intel_updated` sends refreshed IOC and MITRE intelligence.
- `evoguard:audit_event` sends security/audit activity.
- `evoguard:report_event` sends report generation or delivery activity.
- `evoguard:history_reset` clears stale frontend state after backend history is reset.

## Backend API

The realtime status endpoint is:

```text
/realtime_status?source=live
```

It returns whether Socket.IO is enabled, which transport mode is active, server time, and the event names supported by the backend.

Example response fields:

```json
{
  "enabled": true,
  "transport": "socket.io",
  "connected_clients": 1,
  "server_time": "2026-06-03T00:00:00Z"
}
```

## Frontend behavior

- On login, the frontend connects to the backend Socket.IO server.
- When connected, it requests a live sync using `evoguard:request_sync`.
- Every 15 seconds, it sends `evoguard:ping` and receives `evoguard:heartbeat`.
- When realtime is connected, normal stats/history/intel polling slows down and device telemetry continues separately.
- If the socket disconnects, the dashboard automatically returns to polling mode.

## Install commands

Backend:

```powershell
.\.venv\Scripts\python.exe -m pip install flask-socketio
```

Frontend:

```powershell
cd frontend
npm install socket.io-client
```

## Run order

Start backend:

```powershell
cd backend
..\.venv\Scripts\python.exe app.py
```

Start frontend:

```powershell
cd frontend
npm start
```

Then open:

```text
http://localhost:3000
```

The header should show `Realtime Connected` after both servers are running. If it shows `Polling Fallback`, the dashboard still works, but live event updates are being refreshed through normal HTTP polling instead of Socket.IO.
