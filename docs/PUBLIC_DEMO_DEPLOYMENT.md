# Public Demo Deployment

Use this when you want to show EvoGuard Enterprise to an instructor with a public URL.

## Recommended Demo Setup

Deploy two services:

1. Backend API: Flask service.
2. Frontend UI: React static site.

The frontend must know the public backend URL through:

```txt
REACT_APP_API_BASE_URL=https://your-backend-url
```

The backend must allow the public frontend URL through:

```txt
EVOGUARD_CORS_ORIGIN=https://your-frontend-url
```

For more than one frontend origin, separate values with commas.

## Backend Environment Variables

Set these in the backend hosting provider:

```txt
EVOGUARD_SECRET_KEY=change-this-to-a-long-random-value
EVOGUARD_DATABASE_URL=sqlite:///evoguard.db
EVOGUARD_CORS_ORIGIN=https://your-frontend-url
EVOGUARD_DEFAULT_USERNAME=mayed
EVOGUARD_DEFAULT_PASSWORD=mayed123
EVOGUARD_ANALYST_EMAIL=evoguardzu@gmail.com
EVOGUARD_ENABLE_SCHEDULER=false
```

The backend reads the platform `PORT` automatically.

## Backend Start Command

From the repository root:

```txt
cd backend && python app.py
```

Build/install command:

```txt
pip install -r requirements.txt
```

## Frontend Build Settings

Frontend root directory:

```txt
frontend
```

Build command:

```txt
npm install && npm run build
```

Publish/output directory:

```txt
frontend/build
```

Frontend environment variable:

```txt
REACT_APP_API_BASE_URL=https://your-backend-url
```

## Important Demo Notes

- Keep the GitHub repository private unless your instructor asks otherwise.
- Add the instructor as a collaborator if the repo is private.
- Do not upload `.env`, `.venv`, `node_modules`, SQLite database files, or generated logs.
- The current SQLite database is fine for a prototype demo, but production should use PostgreSQL or MySQL.
- If the frontend shows polling fallback, confirm the backend `/realtime_status` endpoint returns `transport: socket.io`.
