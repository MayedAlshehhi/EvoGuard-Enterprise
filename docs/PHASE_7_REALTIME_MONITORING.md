# Phase 7 - Realtime Monitoring

Phase 7 adds Socket.IO realtime updates between the Flask backend and React dashboard.

## What changed

- Backend now supports Flask-SocketIO.
- Frontend now connects with `socket.io-client`.
- Live events pushed through `/ingest_event` broadcast immediately to the dashboard.
- AI response execution logs broadcast immediately after the backend creates them.
- Dashboard header shows `Realtime Connected` when sockets are active.
- If sockets are unavailable, the frontend keeps using the existing polling fallback.

## Backend events

- `evoguard:connected` sends initial live stats, history, and AI response logs.
- `evoguard:new_attack` sends each new live or simulation attack event.
- `evoguard:ai_response` sends autonomous AI response execution logs.
- `evoguard:stats_updated` sends refreshed dashboard statistics.

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

The header should show `Realtime Connected` after both servers are running.
