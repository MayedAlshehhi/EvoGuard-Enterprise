@echo off
setlocal

cd /d "%~dp0"

if not exist ".env" (
  echo EvoGuard backend .env file is missing.
  echo Create it from .env.example before starting the desktop app.
  pause
  exit /b 1
)

if not exist "frontend\.env" (
  echo EvoGuard frontend .env file is missing.
  echo Create it from frontend\.env.example before starting the desktop app.
  pause
  exit /b 1
)

echo Starting EvoGuard Enterprise Desktop...
npm run desktop

endlocal
