@echo off
setlocal
cd /d %~dp0

if not exist .venv (
    echo Creating virtual environment...
    python -m venv .venv
    call .venv\Scripts\python.exe -m pip install --upgrade pip
    call .venv\Scripts\pip.exe install -r requirements.txt
)

call .venv\Scripts\python.exe start.py
