@echo off
setlocal

set "PROJECT_DIR=%~dp0"
set "BACKEND_DIR=%PROJECT_DIR%backend"
set "FRONTEND_DIR=%PROJECT_DIR%frontend"
set "PYTHON_EXE=%PROJECT_DIR%.venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
  set "PYTHON_EXE=%PROJECT_DIR%venv\Scripts\python.exe"
)

if not exist "%PYTHON_EXE%" (
  echo EvoGuard could not find a Python virtual environment.
  echo Expected:
  echo   %PROJECT_DIR%.venv\Scripts\python.exe
  echo or:
  echo   %PROJECT_DIR%venv\Scripts\python.exe
  pause
  exit /b 1
)

if not exist "%PROJECT_DIR%.env" (
  echo EvoGuard backend .env file is missing.
  echo Create it from .env.example before starting the app.
  pause
  exit /b 1
)

if not exist "%FRONTEND_DIR%\.env" (
  echo EvoGuard frontend .env file is missing.
  echo Create it from frontend\.env.example before starting the app.
  pause
  exit /b 1
)

echo Starting EvoGuard Enterprise...

netstat -ano | findstr ":5000" | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
  echo Backend already appears to be running on port 5000.
) else (
  start "EvoGuard Backend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%BACKEND_DIR%'; & '%PYTHON_EXE%' app.py"
)

timeout /t 5 /nobreak >nul

netstat -ano | findstr ":3000" | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
  echo Frontend already appears to be running on port 3000.
) else (
  start "EvoGuard Frontend" powershell -NoExit -ExecutionPolicy Bypass -Command "Set-Location -LiteralPath '%FRONTEND_DIR%'; npm start"
)

timeout /t 8 /nobreak >nul

start http://localhost:3000

echo EvoGuard launched. Backend: http://localhost:5000  Frontend: http://localhost:3000
endlocal
