# NetGuard

**AI-Driven Network Visibility, Threat Detection & Forensics Platform**

A final-year cybersecurity research prototype that provides passive network monitoring, machine-learning-based threat detection, and forensic incident intelligence through a unified SOC-style dashboard.

**Report ↔ code traceability:** see [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) for a section-by-section map. Synthetic / offline material is isolated under [`demo/`](demo/) and `src/data/networkData.ts`.

---

## Architecture Overview

NetGuard is built as a **production-first API-driven architecture** combining real-time TShark packet capture, 5-tuple flow tracking, machine-learning threat detection, and forensic intelligence.

```
REAL NETWORK INTERFACE
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│                 TShark Live Capture Engine                  │
│       Subprocess: tshark.exe -i <iface> -l -T ek            │
└──────────────────────────────┬──────────────────────────────┘
                               │ Streaming NDJSON stdout
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Packet Parser Layer                         │
│   Extracts IP, Ports, MACs, Flags, Length, HTTP, DNS, TLS   │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│   Live Packet Telemetry      │ │   Bidirectional Flow       │
│  Real-time SSE Stream to UI  │ │         Tracker            │
└──────────────────────────────┘ └────────────┬───────────────┘
                                              │ Completed/Expired Flows
                                              ▼
                                 ┌────────────────────────────┐
                                 │   20-dim Feature Vector    │
                                 │       Extraction           │
                                 └────────────┬───────────────┘
                                              │
                                              ▼
                                 ┌────────────────────────────┐
                                 │ Existing ML Ensemble Engine│
                                 │  RF + XGBoost + IsoForest  │
                                 └────────────┬───────────────┘
                                              │
                                              ▼
                                 ┌────────────────────────────┐
                                 │   Database + SSE Alert     │
                                 │   Persistence & Stream     │
                                 └────────────────────────────┘
```

### Live Capture Engine (TShark / Wireshark)

NetGuard programmatically drives the installed Wireshark `tshark.exe` utility for live network capture on Windows and Linux:
- **TShark Executable Detection**: Checks `NETGUARD_TSHARK_PATH`, PATH (`tshark.exe`), and standard Windows installation directories (`C:\Program Files\Wireshark\tshark.exe`).
- **TShark Verification**: Run `tshark --version` to verify installed version and `tshark -D` to discover network interface indices.
- **Packet Telemetry vs Flow Processing**: Individual packets stream immediately to the UI packet table via Server-Sent Events (SSE). Bidirectional 5-tuple flows (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`) are tracked until completion or expiration, whereupon their 20-dim feature vector is evaluated by the ML ensemble.
- **Offline / PCAP Replay Mode**: If TShark is not installed, live capture is reported as unavailable with clear error diagnostics while PCAP file uploading and offline replay remain fully accessible.

## Project Structure

```
NetGuard/
├── app/                        # FastAPI application
│   ├── main.py                 # ASGI entrypoint, lifespan, router wiring
│   ├── database_deps.py        # SQLAlchemy session dependency
│   ├── demo_assets.py          # Synthetic PCAP generator for demos
│   ├── bootstrap.py            # Auto-demo on startup (NETGUARD_AUTO_DEMO=1)
│   └── routers/
│       ├── health.py           # GET /api/health
│       ├── visibility_api.py   # Phase 1 endpoints
│       ├── capture_api.py      # PCAP upload + live capture
│       ├── detection_api.py    # Phase 2 endpoints (scan, alerts, inference)
│       ├── forensics_api.py    # Phase 3 endpoints (SHAP, reports, timeline, IOCs)
│       ├── dashboard_api.py    # SOC overview aggregation
│       └── demo_api.py         # One-click demo loader
│
├── capture/                    # Phase 1: Packet capture layer
│   ├── decoder.py              # Scapy packet → snapshot (passive, no injection)
│   ├── pcap_ingest.py          # Offline PCAP file ingestion
│   ├── live_capture.py         # Real-time passive sniffer (AsyncSniffer)
│   └── pyshark_enrich.py       # Optional tshark/PyShark L7 enrichment
│
├── visibility/                 # Phase 1: Network visibility engine
│   ├── ingest_state.py         # IngestSnapshot — flow/host/DNS/ARP aggregation
│   ├── flow_key.py             # Bidirectional 5-tuple flow ID
│   ├── heuristics.py           # Suspicious traffic pattern detection
│   ├── network_utils.py        # RFC1918 checks, protocol labeling
│   ├── tls_sni.py              # TLS ClientHello SNI extraction
│   └── service.py              # Global snapshot singleton
│
├── detection/                  # Phase 2: AI-based threat detection
│   ├── cicids2017.py           # CICIDS2017 feature names & class labels
│   ├── preprocessing.py        # CSV loader, StandardScaler, batch converter
│   ├── features.py             # Flow dict → numeric feature vector
│   ├── trainer.py              # Synthetic model training (RF + XGB + IsoForest)
│   ├── inference.py            # Ensemble prediction + alert generation
│   └── severity.py             # Confidence → severity mapping
│
├── forensics/                  # Phase 3: Forensic intelligence
│   ├── shap_explain.py         # SHAP TreeExplainer for Random Forest
│   ├── feature_importance.py   # Global CICIDS-aligned weights (SOC charts)
│   ├── correlate.py            # Incident grouping, IOC extraction
│   ├── timeline.py             # Incident timeline builder with kill-chain phases
│   ├── llm_report.py           # LLM-assisted narrative (OpenAI or fallback)
│   ├── exporter.py             # CSV + professional PDF report generator
│   └── chat_service.py         # Analyst chat with MITRE ATT&CK + playbooks
│
├── docs/
│   └── BLUEPRINT.md            # Report ↔ source file mapping (viva traceability)
├── demo/                       # README: synthetic vs main pipeline (no core logic)
│
├── database/                   # SQLAlchemy models & persistence
│   ├── models.py               # All tables: Host, Flow, DNSStat, MLAlert, etc.
│   ├── session.py              # Engine, SessionLocal, init_db()
│   └── persist_visibility.py   # Snapshot ↔ DB serialization
│
├── config.py                   # Project-wide settings (env-var overrides)
├── run_backend.py              # Dev server launcher (uvicorn)
├── requirements.txt            # Python dependencies (by phase)
│
├── src/                        # Frontend (React + Vite + TailwindCSS)
│   ├── App.tsx                 # Main app shell with page routing
│   ├── pages/
│   │   ├── Overview.tsx        # SOC Overview dashboard
│   │   ├── Visibility.tsx      # Phase 1: hosts, flows, graph, DNS, ARP/TLS/HTTP/DHCP
│   │   ├── Detection.tsx       # Phase 2: model status, inference preview
│   │   ├── Alerts.tsx          # Alert center (filterable list)
│   │   ├── Forensics.tsx       # Phase 3: SHAP, reports, timeline
│   │   ├── Assistant.tsx       # AI analyst chat interface
│   │   ├── Codebase.tsx        # Project architecture explorer
│   │   └── Settings.tsx        # Configuration status
│   ├── api/                    # TypeScript API client functions
│   ├── components/             # Sidebar, Topbar, shared UI components
│   └── data/                   # Static demo data for offline rendering
│
├── data/                       # Runtime data directory
│   ├── models/                 # Trained ML model artifacts (.joblib)
│   ├── cicids_uploads/         # Uploaded CICIDS2017 training CSVs
│   └── uploads/                # Uploaded PCAP files
│
├── tests/                      # Pytest test suite
├── run_backend.py              # Dev server launcher (uvicorn)
├── run_demo.bat                # One-click demo for Windows
├── run_demo.sh                 # One-click demo for Linux/macOS
├── index.html                  # Vite entry point
├── vite.config.ts              # Vite dev server + API proxy config
├── package.json                # Node.js dependencies
└── tsconfig.json               # TypeScript configuration
```

## How to Run

### Prerequisites

- **Python 3.10+**
- **Node.js 18+** (for the dashboard frontend)
- **Npcap** (Windows) or **libpcap** (Linux) — required for **live capture only** (PCAP upload and demo mode work without it)

### First-Time Setup

```powershell
# Clone / unzip the project, then:
cd E:\Netguard

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate          # Windows PowerShell
# source venv/bin/activate       # Linux/Mac

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
npm install
```

---

### Windows live capture setup (Npcap)

Live monitoring is **passive only** (Scapy sniff). It sees traffic that arrives on the selected NIC — not every device on Wi-Fi unless you capture at a gateway, SPAN/mirror port, or managed AP/router.

1. **Install Npcap** from [https://npcap.com](https://npcap.com) (Wireshark's installer can also install it). Prefer "WinPcap API-compatible mode" if offered.
2. **Run the backend as Administrator** if Npcap requires elevated rights for your adapter:
   - Open PowerShell **as Administrator**, `cd` to the project, activate `venv`, then `python run_backend.py`.
3. Start the frontend normally (`npm run dev`) in a second terminal.
4. Open **Visibility** → **Live Capture**:
   - Click refresh on the interface list
   - Choose your Ethernet/Wi-Fi adapter
   - Optional duration (`0` = until Stop) and optional BPF filter
   - **Start Live Capture** → watch packets/elapsed update every 2s
   - **Stop Capture** when finished
5. PCAP upload and **Settings → Load demo PCAP** continue to work without Npcap.

**Limitations:** On a normal endpoint you mainly see traffic to/from that host (plus broadcasts like ARP/DHCP/mDNS). Full LAN visibility requires an authorized SPAN/mirror, bridge, or gateway vantage point. NetGuard does not scan, inject, spoof, MITM, or decrypt TLS.

---

### 1. Demo Mode (recommended for viva)

One-click: starts backend, auto-loads synthetic PCAP, runs ML detection, launches dashboard.

```powershell
# Windows — double-click or run:
.\run_demo.bat

# Linux/Mac:
chmod +x run_demo.sh && ./run_demo.sh
```

Or manually:

```powershell
# Terminal 1 — Backend with auto-demo
$env:NETGUARD_AUTO_DEMO = "1"
.\venv\Scripts\Activate
python run_backend.py

# Terminal 2 — Frontend
npm run dev
```

Open **http://localhost:5173** — all pages will be populated with data. Demo-sourced rows are labeled **Demo data** in Visibility.

---

### 2. Development Mode (two terminals)

```powershell
# Terminal 1 — Backend (hot-reload)
.\venv\Scripts\Activate
python run_backend.py

# Terminal 2 — Frontend (hot-reload)
npm run dev
```

Then load data via Settings ("Load demo PCAP"), upload a real PCAP on Visibility, or start live capture.

---

### 3. Backend Only

```powershell
.\venv\Scripts\Activate
python run_backend.py
```

API at **http://127.0.0.1:8000** · Swagger docs at **http://127.0.0.1:8000/docs**

---

### 4. Frontend Only

```powershell
npm run dev
```

Dashboard at **http://localhost:5173** — when the backend is offline, Visibility does **not** invent live traffic; use Settings demo load once the API is up.

---

### 5. Load Demo Data via API

With the backend running:

```powershell
# PowerShell
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/api/demo/load-sample" `
  -ContentType "application/json" -Body '{"run_detection_scan": true}'

# curl (Git Bash / Linux)
curl -X POST http://127.0.0.1:8000/api/demo/load-sample \
     -H "Content-Type: application/json" \
     -d '{"run_detection_scan": true}'
```

### 6. Package a source-only release ZIP

```powershell
.\scripts\package-release.ps1
# Optional: .\scripts\package-release.ps1 -OutDir D:\releases
```

Creates a ZIP under `releases/` excluding `venv/`, `node_modules/`, caches, DBs, uploads, logs, and `.env`. Does not modify project files.

### 7. Tests & typecheck

```powershell
.\venv\Scripts\Activate
pytest -q
npm run typecheck
npm run build
```

## Database Schema

| Table | Purpose | Phase |
|-------|---------|-------|
| `hosts` | Discovered network assets | 1 |
| `flows` | Reconstructed network flows | 1 |
| `dns_stats` | DNS query statistics | 1 |
| `arp_entries` | ARP observations (spoof detection) | 1 |
| `tls_meta` | TLS handshake metadata | 1 |
| `http_meta` | Passive cleartext HTTP `Host:` headers | 1 |
| `dhcp_meta` | Passive DHCP hostname / client IP hints | 1 |
| `bandwidth_bins` | Traffic volume time series | 1 |
| `pcap_uploads` | Uploaded/live PCAP file records | 1 |
| `ml_alerts` | ML-generated threat alerts | 2 |
| `forensic_reports` | Generated incident reports | 3 |

## API Endpoints

### Phase 1 — Visibility
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/visibility/summary` | Host/flow/DNS summary KPIs |
| GET | `/api/visibility/hosts` | Discovered hosts with risk scores |
| GET | `/api/visibility/flows` | Reconstructed flows sorted by volume |
| GET | `/api/visibility/graph` | Communication graph (nodes + edges) |
| GET | `/api/visibility/top-talkers` | Top bandwidth consumers |
| GET | `/api/visibility/protocols` | Protocol distribution |
| GET | `/api/visibility/bandwidth` | Bandwidth time series |
| GET | `/api/visibility/dns` | DNS query log |
| GET | `/api/visibility/arp-tls` | ARP table + TLS metadata |
| GET | `/api/visibility/l7-passive` | HTTP `Host:` + DHCP passive observations |
| GET | `/api/visibility/patterns` | Suspicious pattern alerts |
| POST | `/api/capture/pcap` | Upload PCAP file for analysis |
| GET | `/api/capture/interfaces` | List NICs for live capture |
| POST | `/api/capture/live/start` | Start live passive capture (`interface`, `seconds`, optional `bpfFilter`) |
| POST | `/api/capture/live/stop` | Stop live capture |
| GET | `/api/capture/status` | Live capture state (running, packets, elapsed, stop_reason, …) |

### Phase 2 — Detection
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/detection/status` | Model status and metadata |
| GET | `/api/detection/model-metrics` | Real evaluation metrics from trained model |
| GET | `/api/detection/train-status` | Background training progress |
| POST | `/api/detection/upload-cicids` | Upload CICIDS2017 CSV to trigger real training |
| POST | `/api/detection/scan` | Run ML ensemble on current flows |
| GET | `/api/detection/alerts` | List persisted ML alerts |
| GET | `/api/detection/inference-preview` | Live inference preview (no DB write) |

### Phase 3 — Forensics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/forensics/alerts` | Alert listing for forensic analysis |
| GET | `/api/forensics/alert/{id}/shap` | SHAP explanation for one alert |
| GET | `/api/forensics/feature-importance` | Global CICIDS feature weights (chart) |
| POST | `/api/forensics/alert/{id}/report` | Generate incident report |
| GET | `/api/forensics/incidents` | Correlated incident groups |
| GET | `/api/forensics/timeline/{id}` | Incident timeline for an alert |
| GET | `/api/forensics/iocs` | Extracted indicators of compromise |
| GET | `/api/forensics/mitre/{id}` | MITRE ATT&CK mapping |
| GET | `/api/forensics/export/csv` | CSV export of alerts |
| GET | `/api/forensics/export/pdf` | Professional PDF forensic report |
| POST | `/api/forensics/chat` | Analyst assistant chat |

### Dashboard & Utilities
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check (always public; no bearer required) |
| GET | `/api/dashboard/overview` | Aggregated SOC overview KPIs |
| GET | `/api/dashboard/stats` | Quick numeric stats |
| GET | `/api/dashboard/config` | Runtime configuration |
| POST | `/api/demo/load-sample` | Load synthetic demo data |

## Configuration

All settings can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NETGUARD_DB_PATH` | `data/netguard.db` | SQLite database file path |
| `NETGUARD_DATABASE_URL` | (derived from DB_PATH) | Full SQLAlchemy URL |
| `NETGUARD_MODEL_DIR` | `data/models/` | ML model artifact directory |
| `NETGUARD_MIN_CONF` | `0.45` | Minimum detection confidence |
| `NETGUARD_OPENAI_KEY` | (empty) | OpenAI API key for LLM reports |
| `NETGUARD_OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model name |
| `NETGUARD_CICIDS_CSV` | (empty) | Path to CICIDS2017 CSV to auto-train on startup |
| `NETGUARD_HOST` | `127.0.0.1` | API bind host (**keep localhost** unless behind a secure reverse proxy) |
| `NETGUARD_PORT` | `8000` | API bind port |
| `NETGUARD_AUTO_DEMO` | (empty) | Set to `1` for auto-demo on startup |
| `NETGUARD_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated CORS origins |
| `NETGUARD_API_TOKEN` | (empty) | If set, require `Authorization: Bearer <token>` for all `/api` routes except `/api/health` |
| `VITE_NETGUARD_API_TOKEN` | (empty) | Frontend bearer token (must match backend when auth is enabled) |
| `VITE_API_BASE` | (empty) | Optional absolute API base; leave empty when using the Vite proxy |

### Deployment notes

- Bind with `NETGUARD_HOST=127.0.0.1` unless the API sits behind HTTPS + authentication (reverse proxy).
- Set `NETGUARD_API_TOKEN` and the matching Vite env var; never commit tokens to source.
- Restrict `NETGUARD_ALLOWED_ORIGINS` to your real dashboard origin(s).
- Live capture still needs Npcap/libpcap and appropriate privileges on the capture host.

## Design Principles

- **Passive only**: No active scanning or probing. All data is derived from captured traffic metadata.
- **Production-first**: The frontend dashboard relies on live backend API services. Empty live/PCAP sources show empty-state UI (not fake hosts).
- **Modular pipeline**: Each phase is a self-contained Python package with clean imports.
- **Shared state store**: SQLite database serves as the single source of truth across modules.
- **Offline capable**: Functions gracefully without OpenAI keys or Npcap/tshark; uses fallback logic throughout.
- **Demo-friendly**: Synthetic data generators and auto-demo mode for viva presentations; demo data is labeled explicitly.

## ML Models

The system requires real data for meaningful ML results. You can now train the system directly via the API:

1. **API Ingestion**: Upload a real CICIDS2017 CSV file via `POST /api/detection/upload-cicids`. This triggers background training (`trainer.py`) and immediately provisions the real Random Forest, XGBoost, and Isolation Forest models.
2. **Environment Variable**: Set `NETGUARD_CICIDS_CSV=/path/to/Friday-WorkingHours.pcap_ISCX.csv` to auto-train during backend startup.

> **Note**: If no real data is provided, the backend falls back to an isolated `synthetic_fallback` model to prevent crashes. The dashboard clearly labels this state and will prompt you to upload a real dataset.

## License

Academic project — University of Mumbai, Final Year B.E. (Computer Engineering).
