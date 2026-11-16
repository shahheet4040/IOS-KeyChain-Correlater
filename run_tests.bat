@echo off
if exist .venv\Scripts\python.exe (
    .\.venv\Scripts\python.exe -m pytest %*
) else (
    python run_tests.py %*
)
