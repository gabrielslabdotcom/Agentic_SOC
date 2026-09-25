@echo off
setlocal
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0network-isolation.ps1"
exit /b %ERRORLEVEL%
