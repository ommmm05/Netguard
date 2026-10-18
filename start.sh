#!/usr/bin/env bash
# ═════════════════════════════════════════════════════════════════════
#  NetGuard — One-Command Single-Terminal Launcher
#  Supports: Linux, macOS, WSL, Windows Git Bash / MSYS2 / Cygwin
#  Usage:
#      chmod +x start.sh
#      ./start.sh
# ═════════════════════════════════════════════════════════════════════

set -e

# Change to project root directory
cd "$(dirname "$0")"

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      NetGuard — AI-Driven Network Security & SOC Platform      ║"
echo "║                   ONE-COMMAND LAUNCHER                         ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# ─────────────────────────────────────────────────────────────
# 1. Detect Python
# ─────────────────────────────────────────────────────────────
echo "[1/5] Checking Python environment..."
PY=""
if command -v python3 &>/dev/null; then
    PY="python3"
elif command -v python &>/dev/null; then
    PY="python"
else
    echo "  [ERROR] Python is not installed or not in PATH."
    echo "  Please install Python 3.10+ from https://www.python.org/"
    exit 1
fi

PY_VERSION=$($PY --version 2>&1)
echo "  [OK] $PY_VERSION detected."

# ─────────────────────────────────────────────────────────────
# 2. Detect Node.js & npm
# ─────────────────────────────────────────────────────────────
echo "[2/5] Checking Node.js and npm..."
if ! command -v node &>/dev/null || ! command -v npm &>/dev/null; then
    echo "  [ERROR] Node.js or npm is not installed or not in PATH."
    echo "  Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node --version 2>&1)
NPM_VERSION=$(npm --version 2>&1)
echo "  [OK] Node.js $NODE_VERSION and npm $NPM_VERSION detected."

# ─────────────────────────────────────────────────────────────
# 3. Setup / Activate Virtual Environment & Dependencies
# ─────────────────────────────────────────────────────────────
echo "[3/5] Setting up Python virtual environment..."
VENV_ACTIVATED=0

if [ -f "venv/bin/activate" ]; then
    # POSIX / Linux / macOS / WSL
    source venv/bin/activate
    VENV_ACTIVATED=1
elif [ -f "venv/Scripts/activate" ]; then
    # Windows Git Bash / MSYS2
    source venv/Scripts/activate
    VENV_ACTIVATED=1
else
    echo "  [*] Creating new virtual environment in ./venv ..."
    $PY -m venv venv
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
        VENV_ACTIVATED=1
    elif [ -f "venv/Scripts/activate" ]; then
        source venv/Scripts/activate
        VENV_ACTIVATED=1
    fi
fi

if [ $VENV_ACTIVATED -eq 1 ]; then
    echo "  [OK] Virtual environment activated."
else
    echo "  [!] Virtual environment could not be activated, using system Python."
fi

# Verify / install requirements
if [ -f "requirements.txt" ]; then
    echo "  [*] Verifying Python dependencies (requirements.txt)..."
    python -m pip install -r requirements.txt --quiet --disable-pip-version-check || {
        echo "  [WARNING] pip install returned non-zero code; proceeding with installed packages."
    }
fi

# Verify / install npm dependencies
if [ ! -d "node_modules" ]; then
    echo "  [*] Installing npm dependencies (first run)..."
    npm install
fi
echo "  [OK] Dependencies ready."

# ─────────────────────────────────────────────────────────────
# 4. Cleanup Handler (Single-Terminal Exit)
# ─────────────────────────────────────────────────────────────
BACKEND_PID=""

cleanup() {
    # Disable trap so cleanup does not trigger repeatedly
    trap - INT TERM EXIT
    echo ""
    echo "────────────────────────────────────────────────────────────────"
    echo "[*] Stopping NetGuard services..."

    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo "  [*] Stopping backend process (PID: $BACKEND_PID)..."
        kill -TERM "$BACKEND_PID" 2>/dev/null || true
        # Give backend 2 seconds to shut down gracefully
        for i in {1..4}; do
            if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
                break
            fi
            sleep 0.5
        done
        # Force kill if still running
        if kill -0 "$BACKEND_PID" 2>/dev/null; then
            kill -KILL "$BACKEND_PID" 2>/dev/null || true
        fi
    fi

    # Kill any lingering python processes running run_backend.py on Windows Git Bash
    if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* ]]; then
        powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"CommandLine LIKE '%run_backend.py%'\" | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }" 2>/dev/null || true
    fi

    echo "  [✓] Backend stopped."
    echo "  [✓] NetGuard shutdown complete."
    echo "────────────────────────────────────────────────────────────────"
    exit 0
}

trap cleanup INT TERM EXIT

# ─────────────────────────────────────────────────────────────
# 5. Start Backend and Frontend in Single Terminal
# ─────────────────────────────────────────────────────────────
echo "[4/5] Launching FastAPI Backend..."
export NETGUARD_AUTO_DEMO=1

# Start backend in background
python run_backend.py &
BACKEND_PID=$!

echo "  [*] Backend started in background (PID: $BACKEND_PID)."
echo "  [*] Waiting for backend health check..."

READY=0
for i in {1..20}; do
    if curl -s http://127.0.0.1:8000/api/health >/dev/null 2>&1 || curl -s http://127.0.0.1:8000/api/capture/status >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 1
done

if [ $READY -eq 1 ]; then
    echo "  [OK] Backend is live at http://127.0.0.1:8000"
else
    echo "  [!] Backend did not respond within 20s, but proceeding..."
fi

# Auto-open browser in background
open_browser() {
    sleep 3
    URL="http://localhost:5173"
    if command -v xdg-open &>/dev/null; then
        xdg-open "$URL" 2>/dev/null || true
    elif command -v open &>/dev/null; then
        open "$URL" 2>/dev/null || true
    elif command -v cmd.exe &>/dev/null; then
        cmd.exe /c start "$URL" 2>/dev/null || true
    elif command -v start &>/dev/null; then
        start "$URL" 2>/dev/null || true
    elif command -v explorer.exe &>/dev/null; then
        explorer.exe "$URL" 2>/dev/null || true
    fi
}
open_browser &

echo "[5/5] Launching Vite Frontend..."
echo ""
echo "┌──────────────────────────────────────────────────────────────┐"
echo "│  NETGUARD SOC IS RUNNING                                     │"
echo "│                                                              │"
echo "│  • Frontend Dashboard : http://localhost:5173                │"
echo "│  • Backend API        : http://127.0.0.1:8000                │"
echo "│  • API Documentation  : http://127.0.0.1:8000/docs           │"
echo "│                                                              │"
echo "│  [Tip] Press Ctrl+C anytime to stop BOTH frontend & backend  │"
echo "└──────────────────────────────────────────────────────────────┘"
echo ""

# Run frontend in foreground; when user stops it with Ctrl+C, trap cleanup runs
npm run dev
