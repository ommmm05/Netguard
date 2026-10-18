#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  NetGuard Demo Mode — macOS / Linux
#  Starts backend, loads synthetic PCAP + ML scan, opens dashboard
#  Usage: chmod +x run_demo.sh && ./run_demo.sh
# ─────────────────────────────────────────────────────────────

set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  NetGuard — AI-Driven Network Visibility, Threat Detection  ║"
echo "║              & Forensics Platform                           ║"
echo "║                                                              ║"
echo "║  DEMO MODE                                                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Check Python ──
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo "[ERROR] Python not found. Install Python 3.10+ and add to PATH."
    exit 1
fi
PY=$(command -v python3 || command -v python)
echo "[*] Using Python: $PY"

# ── Activate venv if available ──
if [ -f "venv/bin/activate" ]; then
    echo "[*] Activating virtual environment..."
    source venv/bin/activate
else
    echo "[!] No venv found. Using system Python."
    echo "    Tip: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
fi

# ── Set demo environment ──
export NETGUARD_AUTO_DEMO=1

echo ""
echo "[*] Starting backend with NETGUARD_AUTO_DEMO=1 ..."
echo "    This will:"
echo "      1. Initialize SQLite database"
echo "      2. Generate synthetic PCAP"
echo "      3. Ingest PCAP through passive pipeline"
echo "      4. Run ML detection (RF + XGBoost + IsolationForest)"
echo "      5. Populate alerts, visibility data, and forensics"
echo ""

# ── Start backend in background (new terminal window on macOS) ──
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS — open a new Terminal window for the backend
    osascript -e "tell application \"Terminal\" to do script \"cd '$(pwd)' && source venv/bin/activate 2>/dev/null; NETGUARD_AUTO_DEMO=1 python run_backend.py\""
else
    # Linux — background process
    $PY run_backend.py &
    BACKEND_PID=$!
    trap "kill $BACKEND_PID 2>/dev/null; exit" INT TERM
fi

# ── Wait for backend to be ready ──
echo "[*] Waiting for backend to start..."
sleep 6

# ── Check if backend is up ──
if ! curl -s http://127.0.0.1:8000/api/health >/dev/null 2>&1; then
    echo "[*] Backend still starting, waiting 5 more seconds..."
    sleep 5
fi

# ── Check Node.js / npm ──
if ! command -v npm &>/dev/null; then
    echo "[!] npm not found. Backend is running at http://127.0.0.1:8000"
    echo "    Install Node.js 18+ for the dashboard UI."
    echo "    Or open http://127.0.0.1:8000/docs for API explorer."
    exit 0
fi

# ── Install deps if needed ──
if [ ! -d "node_modules" ]; then
    echo "[*] Installing Node.js dependencies (first run)..."
    npm install
fi

echo ""
echo "[*] Starting frontend dashboard..."
echo ""
echo "┌─────────────────────────────────────────────────┐"
echo "│  Backend:   http://127.0.0.1:8000               │"
echo "│  Dashboard: http://localhost:5173                │"
echo "│  API docs:  http://127.0.0.1:8000/docs          │"
echo "│                                                  │"
echo "│  Press Ctrl+C to stop the frontend              │"
echo "│  Close the Backend Terminal to stop API server  │"
echo "└─────────────────────────────────────────────────┘"
echo ""

# ── Auto-open browser on macOS ──
if [[ "$OSTYPE" == "darwin"* ]]; then
    sleep 3 && open http://localhost:5173 &
fi

npm run dev
