@echo off
title Server - Saksham Varshney 44300
cd /d "%~dp0"
if not exist server.exe (
    echo server.exe not found. Run build.bat first.
    pause
    exit /b 1
)
server.exe
pause