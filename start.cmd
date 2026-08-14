@echo off
title DoctorateTs One-Click Start
cd /d "%~dp0"

echo ============================================
echo   DoctorateTs one-click start (quick mode)
echo ============================================
echo.

if not exist node_modules (
  echo [first run] installing dependencies...
  call pnpm install
  if errorlevel 1 goto :err
)

echo Starting server (skip network update, use local data)...
start "DoctorateTs Server" cmd /k "pnpm run watch"
echo Waiting for server and opening admin dashboard...
node scripts/open-dashboard.js
if errorlevel 1 (
  echo Server may have failed to start. Check the "DoctorateTs Server" window log.
)
echo.
echo NOTE: admin API needs data/config.json "admin": { "enable": true, "token": "..." }
pause
exit /b 0

:err
echo.
echo [error] startup failed. See log above.
pause
exit /b 1
