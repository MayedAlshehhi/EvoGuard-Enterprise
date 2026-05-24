# EvoGuard Enterprise

EvoGuard Enterprise is an Agentic AI Cyber Defense Platform prototype for SOC-style monitoring, AI attack analysis, live event intake, simulation, threat intelligence, autonomous response logging, reports, and real-time dashboard monitoring.

## Demo Links

- GitHub Pages frontend demo: <https://MayedAlshehhi.github.io/EvoGuard-Enterprise>
- GitHub repository: <https://github.com/MayedAlshehhi/EvoGuard-Enterprise>

> GitHub Pages hosts the React frontend only. Full backend features require running or deploying the Flask backend.

## Demo Login

```txt
Username: mayed
Password: mayed123
```

## Local Backend

```powershell
cd backend
..\ .venv\Scripts\Activate.ps1
python app.py
```

If activating from the project root:

```powershell
.\.venv\Scripts\Activate.ps1
cd backend
python app.py
```

## Local Frontend

```powershell
cd frontend
npm install
npm start
```

Open:

```txt
http://localhost:3000
```

## Technology Stack

- React
- Flask
- SQLite
- Flask-SocketIO
- React Leaflet
- Recharts
- scikit-learn / joblib AI model artifacts

## Notes

- The project is an advanced senior-project prototype, not a production SOC deployment.
- SQLite is used for prototype storage.
- Production deployment should use a hosted backend, stronger authentication, persistent database, and managed secrets.
