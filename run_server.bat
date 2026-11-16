@echo off
title iOS Keychain Correlator - Web Server
cd /d "%~dp0"
echo ==============================================================
echo  Launching iOS Keychain Correlator Forensic Web Server...
echo ==============================================================
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" run_server.py
) else (
    python run_server.py
)
pause
