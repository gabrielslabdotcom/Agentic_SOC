@echo off
setlocal
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0network-deisolation.ps1"
exit /b %ERRORLEVEL%
