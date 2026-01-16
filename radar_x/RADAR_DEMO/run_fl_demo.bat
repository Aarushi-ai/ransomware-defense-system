@echo off
TITLE RADAR-X Federated Learning Demo
COLOR 0B

ECHO ===================================================
ECHO     RADAR-X FEDERATED LEARNING LIVE DEMO
ECHO ===================================================
ECHO.
ECHO This script will launch:
ECHO   1. Federated Server (Aggregator)
ECHO   2. Client A: Hospital (Data Node)
ECHO   3. Client B: Bank (Data Node)
ECHO.
ECHO Setting up environment...

IF EXIST "venv" (
    call venv_demo\Scripts\activate
) ELSE (
    ECHO [WARNING] Virtual environment not found. Using global Python.
)

ECHO.
ECHO [1/3] Launching SERVER...
start "FL SERVER" cmd /k "python Stage2_Learn/federated_server_integrated.py"

TIMEOUT /T 5

ECHO [2/3] Launching HOSPITAL Client...
start "CLIENT: HOSPITAL" cmd /k "python Stage2_Learn/federated_client_integrated.py --data Stage2_Learn/data_hospital.csv"

TIMEOUT /T 2

ECHO [3/3] Launching BANK Client...
start "CLIENT: BANK" cmd /k "python Stage2_Learn/federated_client_integrated.py --data Stage2_Learn/data_bank.csv"

ECHO.
ECHO [SUCCESS] All nodes active! Watch the other windows.
ECHO.
PAUSE
