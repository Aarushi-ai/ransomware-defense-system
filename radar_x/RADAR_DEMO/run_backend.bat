@echo off
TITLE RADAR-X1 Backend System
COLOR 0E

ECHO ===================================================
ECHO       RADAR-X1 BACKEND ENGINE
ECHO ===================================================
ECHO.

:: Activate Environment if exists
IF EXIST "venv_demo" (
    ECHO [INFO] Loading secure environment...
    call venv_demo\Scripts\activate
) ELSE (
    ECHO [WARNING] Virtual environment not found. Using global Python.
)

ECHO [START] Launching Integrated Backend...
python -c "from integrated_system import IntegratedBackend; b=IntegratedBackend(); b.start(); b.monitoring_loop()"

PAUSE
