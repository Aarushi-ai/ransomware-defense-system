@echo off
TITLE RADAR-X1 Defense System - Portable Launcher
COLOR 0A
ECHO ===================================================
ECHO       RADAR-X1 RANSOMWARE DEFENSE SYSTEM
ECHO              Portable Launcher
ECHO ===================================================
ECHO.

:: Step 1: Check for Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    COLOR 0C
    ECHO [ERROR] Python is not installed or not in PATH.
    ECHO Please install Python 3.9+ to continue.
    PAUSE
    EXIT
)

:: Step 2: Initialize Environment
IF NOT EXIST "venv_demo" (
    ECHO [INIT] Creating secure virtual environment - First Run...
    python -m venv venv_demo
    call venv_demo\Scripts\activate
    
    ECHO [INIT] Installing dependencies...
    pip install -r requirements.txt
    
    ECHO [INIT] Installing notification support...
    pip install plyer
    
    ECHO [SUCCESS] Environment ready!
) ELSE (
    ECHO [INFO] Loading secure environment...
    call venv_demo\Scripts\activate
)

:: Step 3: Launch System
ECHO.
ECHO [LAUNCH] Starting RADAR-X Dashboard...
ECHO [INFO] Press Ctrl+C to close.
ECHO.

ECHO [LAUNCH] Starting Backend Engine...
start "RADAR-X Backend" cmd /k "call run_backend.bat"
timeout /t 5 >nul

streamlit run dashboard.py

PAUSE
