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
start "FL Server" cmd /k "venv_demo\Scripts\python Stage2_Learn/federated_server_integrated.py"
timeout /t 5

start "Hospital (Client 1)" cmd /k "venv_demo\Scripts\python Stage2_Learn/federated_client_integrated.py --server 127.0.0.1:9999 --org Hospital --data Stage2_Learn/data_hospital.csv"
start "Bank (Client 2)" cmd /k "venv_demo\Scripts\python Stage2_Learn/federated_client_integrated.py --server 127.0.0.1:9999 --org Bank --data Stage2_Learn/data_bank.csv"
start "University (Client 3)" cmd /k "venv_demo\Scripts\python Stage2_Learn/federated_client_integrated.py --server 127.0.0.1:9999 --org University --data Stage2_Learn/data_university.csv"

ECHO.
ECHO [SUCCESS] All nodes active! Watch the other windows.
ECHO.
PAUSE
