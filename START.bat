@echo off
setlocal EnableDelayedExpansion
title NetGuard — One-Click Launcher
color 0A

REM ════════════════════════════════════════════════════════════════
REM  NetGuard — ONE CLICK LAUNCHER (Windows)
REM  Handles: Python venv, pip install, npm install,
REM           backend startup, frontend startup, browser open
REM  Just double-click this file — no manual steps needed.
REM ════════════════════════════════════════════════════════════════

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║   NetGuard — AI-Driven Network Visibility ^& Detection       ║
echo  ║               ONE-CLICK LAUNCHER                            ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

REM ── Make sure we are in the project folder ──
cd /d "%~dp0"
echo [*] Working directory: %CD%
echo.

REM ════════════════════════════════════════════════════════════════
REM  STEP 1: Check Python
REM ════════════════════════════════════════════════════════════════
echo [1/6] Checking Python...
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Python not found!
    echo  Please install Python 3.10+ from https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo  [OK] Python %PY_VER% found.
echo.

REM ════════════════════════════════════════════════════════════════
REM  STEP 2: Check Node.js / npm
REM ════════════════════════════════════════════════════════════════
echo [2/6] Checking Node.js...
where npm >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Node.js / npm not found!
    echo  Please install Node.js 18+ from https://nodejs.org/
    echo.
    pause
    exit /b 1
)
for /f "tokens=1 delims=" %%v in ('node --version 2^>^&1') do set NODE_VER=%%v
echo  [OK] Node.js %NODE_VER% found.
echo.

REM ════════════════════════════════════════════════════════════════
REM  STEP 3: Create virtual environment (first time only)
REM ════════════════════════════════════════════════════════════════
echo [3/6] Setting up Python virtual environment...
if not exist "venv\Scripts\activate.bat" (
    echo  [*] Creating venv — this takes ~10 seconds on first run...
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
) else (
    echo  [OK] Virtual environment already exists.
)

REM ── Activate venv ──
call venv\Scripts\activate.bat
echo  [OK] Virtual environment activated.
echo.

REM ════════════════════════════════════════════════════════════════
REM  STEP 4: Install Python dependencies (first time or if changed)
REM ════════════════════════════════════════════════════════════════
echo [4/6] Installing Python dependencies...
echo  [*] Running: pip install -r requirements.txt
echo  [*] (Skip if already installed — may take 1-3 min on first run)
echo.
pip install -r requirements.txt --quiet --disable-pip-version-check
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
)
echo  [OK] Python dependencies ready.
echo.

REM ════════════════════════════════════════════════════════════════
REM  STEP 5: Install Node.js dependencies (first time only)
REM ════════════════════════════════════════════════════════════════
echo [5/6] Installing Node.js dependencies...
if not exist "node_modules" (
    echo  [*] Running: npm install  (first run — may take 1-2 min)
    call npm install
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] npm install failed. Check your internet connection.
        pause
        exit /b 1
    )
    echo  [OK] Node.js dependencies installed.
) else (
    echo  [OK] node_modules already exists, skipping npm install.
)
echo.

REM ════════════════════════════════════════════════════════════════
REM  STEP 6: Start backend + frontend
REM ════════════════════════════════════════════════════════════════
echo [6/6] Launching NetGuard...
echo.

REM ── Set demo mode ──
set NETGUARD_AUTO_DEMO=1

REM ── Start Backend in a new CMD window ──
echo  [*] Starting Backend (FastAPI) in a new window...
start "NetGuard Backend" cmd /k "cd /d %CD% && call venv\Scripts\activate.bat && set NETGUARD_AUTO_DEMO=1 && echo. && echo  [NetGuard Backend] Starting... && echo. && python run_backend.py"

REM ── Wait for backend to initialize ──
echo  [*] Waiting for backend to initialize (8 seconds)...
timeout /t 8 /nobreak >nul

REM ── Health check ──
curl -s http://127.0.0.1:8000/api/health >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  [*] Backend still booting, waiting 6 more seconds...
    timeout /t 6 /nobreak >nul
)

REM ── Auto-open browser after 4 seconds ──
echo  [*] Browser will open in 4 seconds...
start "" cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:5173"

REM ── Start Frontend ──
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  NETGUARD IS RUNNING                                        ║
echo  ║                                                              ║
echo  ║  Backend  :  http://127.0.0.1:8000                          ║
echo  ║  Dashboard:  http://localhost:5173       (opens in browser)  ║
echo  ║  API Docs :  http://127.0.0.1:8000/docs                     ║
echo  ║                                                              ║
echo  ║  Press Ctrl+C HERE to stop both frontend and backend         ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

call npm run dev

REM ── Cleanup on exit ──
echo.
echo [*] Frontend stopped. Shutting down NetGuard Backend...
taskkill /F /FI "WINDOWTITLE eq NetGuard Backend*" >nul 2>&1
echo [*] All NetGuard services stopped.
pause
