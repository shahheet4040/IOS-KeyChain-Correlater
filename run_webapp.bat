@echo off
title iOS Keychain Correlator - Web Dashboard
cd /d "%~dp0"

echo ======================================================================
echo  Launching iOS Keychain Correlator Web Application
echo ======================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [!] Python virtual environment not found. Please run setup first.
    pause
    exit /b 1
)

.\.venv\Scripts\python.exe run_webapp.py 8888
pause
