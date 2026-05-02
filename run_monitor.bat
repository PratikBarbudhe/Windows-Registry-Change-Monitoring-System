@echo off
REM Windows Registry Change Monitoring System helper script
REM Usage:
REM   run_monitor.bat baseline
REM   run_monitor.bat compare

set PYTHON=python
set SCRIPT=%~dp0src\monitor.py
set BASELINE=%~dp0registry_baseline.json
set ALERTS=%~dp0registry_alerts.json

if "%1"=="baseline" (
    echo Creating registry baseline...
    %PYTHON% "%SCRIPT%" --create-baseline --baseline "%BASELINE%"
    exit /b %ERRORLEVEL%
)

if "%1"=="compare" (
    echo Comparing current registry state to baseline...
    %PYTHON% "%SCRIPT%" --compare --baseline "%BASELINE%" --alerts "%ALERTS%"
    exit /b %ERRORLEVEL%
)

echo Usage: run_monitor.bat [baseline|compare]
exit /b 1
