@echo off
REM Windows Registry Change Monitoring launcher
REM Usage:
REM   scripts\run_monitor.bat create
REM   scripts\run_monitor.bat load

set PYTHON=python

if "%1"=="create" (
    %PYTHON% -m app.main --mode create --interval 10
    exit /b %ERRORLEVEL%
)

if "%1"=="load" (
    %PYTHON% -m app.main --mode load --interval 10
    exit /b %ERRORLEVEL%
)

echo Usage: scripts\run_monitor.bat [create^|load]
exit /b 1

