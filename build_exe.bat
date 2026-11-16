@echo off
title Build Standalone Forensic Executable
cd /d "%~dp0"

echo ======================================================================
echo  Building Standalone Windows Executable for iOS Keychain Correlator
echo ======================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [!] Python virtual environment not found. Please run setup first.
    pause
    exit /b 1
)

.\.venv\Scripts\python.exe build_exe.py

echo.
echo Build script finished. Check the dist\ folder for the compiled application.
pause
