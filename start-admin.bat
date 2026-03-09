@echo off
setlocal
cd /d %~dp0

if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
    call .venv\Scripts\python.exe -m pip install --upgrade pip
    call .venv\Scripts\pip.exe install -r requirements.txt
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -Verb RunAs -WorkingDirectory '%cd%' -FilePath '%cd%\start-admin-elevated.bat'"
