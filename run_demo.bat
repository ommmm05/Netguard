@echo off
REM ─────────────────────────────────────────────────────────────
REM  NetGuard Demo Mode — Windows
REM  Starts backend, loads synthetic PCAP + ML scan, opens dashboard
REM ─────────────────────────────────────────────────────────────

title NetGuard Demo Mode

echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  NetGuard — AI-Driven Network Visibility, Threat Detection  ║
echo  ║              ^& Forensics Platform                           ║
echo  ║                                                              ║
echo  ║  DEMO MODE                                                   ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

REM ── Check Python ──
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found. Install Python 3.10+ and add to PATH.
    pause
    exit /b 1
)

REM ── Check virtual environment ──
if exist "venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo [!] No venv found. Using system Python.
    echo     Tip: python -m venv venv ^&^& venv\Scripts\activate ^&^& pip install -r requirements.txt
)

REM ── Set demo environment ──
set NETGUARD_AUTO_DEMO=1

echo.
echo [*] Starting backend with NETGUARD_AUTO_DEMO=1 ...
echo     This will:
echo       1. Initialize SQLite database
echo       2. Generate synthetic PCAP
echo       3. Ingest PCAP through passive pipeline
echo       4. Run ML detection (RF + XGBoost + IsolationForest)
echo       5. Populate alerts, visibility data, and forensics
echo.

REM ── Start backend in background ──
start "NetGuard Backend" cmd /c "python run_backend.py"

REM ── Wait for backend to be ready ──
echo [*] Waiting for backend to start...
timeout /t 6 /nobreak >nul

REM ── Check if backend is up ──
curl -s http://127.0.0.1:8000/api/health >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [*] Backend still starting, waiting 5 more seconds...
    timeout /t 5 /nobreak >nul
)

REM ── Check Node.js ──
where npm >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] npm not found. Backend is running at http://127.0.0.1:8000
    echo     Install Node.js 18+ for the dashboard UI.
    echo     Or open http://127.0.0.1:8000/docs for API explorer.
    pause
    exit /b 0
)

REM ── Install deps if needed ──
if not exist "node_modules" (
    echo [*] Installing Node.js dependencies (first run)...
    call npm install
)

echo.
echo [*] Starting frontend dashboard...
echo.
echo  ┌─────────────────────────────────────────────────┐
echo  │  Backend:   http://127.0.0.1:8000               │
echo  │  Dashboard: http://localhost:5173                │
echo  │  API docs:  http://127.0.0.1:8000/docs          │
echo  │                                                  │
echo  │  Press Ctrl+C in this window to stop frontend    │
echo  │  Close the Backend window to stop API server     │
echo  └─────────────────────────────────────────────────┘
echo.

call npm run dev
