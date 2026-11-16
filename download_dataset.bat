@echo off
title Public Forensic Dataset Downloader
cd /d "%~dp0"

echo ======================================================================
echo  Download & Setup Real-World Forensic Benchmark Datasets
echo ======================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [!] Python virtual environment not found.
    pause
    exit /b 1
)

.\.venv\Scripts\python.exe download_public_dataset.py %*
pause
