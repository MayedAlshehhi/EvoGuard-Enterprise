@echo off
setlocal

echo Stopping EvoGuard local servers...

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":3000" ^| findstr "LISTENING"') do (
  taskkill /PID %%a /F >nul 2>&1
)

for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":5000" ^| findstr "LISTENING"') do (
  taskkill /PID %%a /F >nul 2>&1
)

echo EvoGuard local servers stopped.
pause
endlocal
