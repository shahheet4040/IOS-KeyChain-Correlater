@echo off
title iOS Keychain Correlator - Forensic Toolkit GUI
echo Launching iOS Keychain Correlator GUI...
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    start "" ".venv\Scripts\pythonw.exe" -m correlator.gui
) else (
    start "" python -m correlator.gui
)
exit
