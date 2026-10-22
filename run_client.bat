@echo off
title Client - Saksham Varshney 44300
cd /d "%~dp0"
if not exist client.exe (
    echo client.exe not found. Run build.bat first.
    pause
    exit /b 1
)
client.exe
pause