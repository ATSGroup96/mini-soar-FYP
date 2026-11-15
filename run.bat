@echo off
REM ============================================================================
REM  Mini-SOAR launcher for Windows. Same commands as start.ps1:
REM    run.bat                      start everything
REM    run.bat scan [ip]            start + scan
REM    run.bat update               rebuild + sync CVEs + scan
REM    run.bat enroll <ip> [admin]  prepare a lab host for auto-fix
REM    run.bat check <ip>           test a host
REM    run.bat logs [service]       live logs
REM    run.bat stop                 stop everything
REM  Works for both Windows modes (.env NETWORK_MODE=nat -> Docker Desktop,
REM  NETWORK_MODE=native -> no Docker). It only exists so PowerShell's script
REM  policy does not get in the way.
REM ============================================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
