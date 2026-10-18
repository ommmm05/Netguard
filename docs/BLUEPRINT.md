# NetGuard — Report ↔ Implementation Blueprint

This document maps the **written report / viva narrative** to concrete **files and APIs** so reviewers can trace every claim in the ZIP.

---

## Phase 1 — Network Visibility Module

| Report topic | Implementation | Persistence (SQLite) |
|--------------|------------------|----------------------|
| PCAP upload | `capture/pcap_ingest.py`, `app/routers/capture_api.py` `POST /api/capture/pcap` | `pcap_uploads` |
| Live capture | `capture/live_capture.py`, `capture_api` `live/start`, `live/stop` | `pcap_uploads.source=live` |
| Packet decode | `capture/decoder.py` (Scapy, passive) | — |
| Flow reconstruction | `visibility/flow_key.py`, `visibility/ingest_state.py` `FlowAgg` | `flows` |
| Asset discovery | `ingest_state.hosts_as_list()`, heuristics in `visibility/heuristics.py` | `hosts` |
| DNS metadata | `decoder.py` → `register_dns` | `dns_stats` |
| ARP | `decoder.py` → `register_arp` | `arp_entries` |
| DHCP (options 12/50/yiaddr) | `decoder.py` → `register_dhcp_observation` | `dhcp_meta` |
| HTTP `Host:` (cleartext) | `decoder.py` → `register_http_host` | `http_meta` |
| TLS ClientHello SNI | `visibility/tls_sni.py`, `register_tls` | `tls_meta` |
| Protocol breakdown / bandwidth | `ingest_state.protocol_distribution`, `bandwidth_series` | `bandwidth_bins` |
| Comm graph | `ingest_state.comm_nodes`, `comm_edges` | derived from `flows` |
| Suspicious patterns | `ingest_state.run_pattern_hooks`, `visibility/heuristics.py` | API only `/visibility/patterns` |
| Dashboard APIs | `app/routers/visibility_api.py` | — |
| L7 passive bundle | `GET /api/visibility/l7-passive` | snapshot + DB on persist |

---

## Phase 2 — AI-Based Threat Detection

| Report topic | Implementation | Persistence |
|--------------|----------------|-------------|
| CICIDS2017 naming | `detection/cicids2017.py` | — |
| Preprocessing utilities | `detection/preprocessing.py` | — |
| Feature vector from flow | `detection/features.py` | — |
| RF / XGB / IsoForest | `detection/trainer.py`, `detection/inference.py` | `data/models/*.joblib` |
| Confidence + severity | `detection/severity.py`, `inference.predict_on_vector` | — |
| Alerts | `detection_api.py` `POST /scan`, `execute_detection_scan` | `ml_alerts` |
| Live preview (no DB write) | `GET /api/detection/inference-preview` | — |

---

## Phase 3 — Forensics & Incident Intelligence

| Report topic | Implementation | Persistence |
|--------------|----------------|-------------|
| SHAP (TreeSHAP) | `forensics/shap_explain.py`, `GET /api/forensics/alert/{id}/shap` | `ml_alerts.shap_top` |
| Global feature chart | `forensics/feature_importance.py`, `GET /api/forensics/feature-importance` | — (weights documented in code) |
| Incident correlation | `forensics/correlate.py` `build_incident_groups` | `GET /api/forensics/incidents` |
| Timeline | `forensics/timeline.py` `build_full_timeline`, `as_timeline_events` | `forensic_reports.timeline` JSON |
| LLM summary + remediation | `forensics/llm_report.py`, `POST /api/forensics/alert/{id}/report` | `forensic_reports` |
| IOC extraction | `forensics/correlate.py` `get_iocs`, chat re-exports | `GET /api/forensics/iocs` |
| MITRE mapping | `forensics/chat_service.py` `get_mitre_mapping` | `GET /api/forensics/mitre/{id}` |
| PDF / CSV export | `forensics/exporter.py`, `forensics_api` `/export/pdf`, `/export/csv` | — |
| Analyst chat | `forensics/chat_service.py` `POST /api/forensics/chat` | — |

---

## Dashboard (React)

| Page | File | Primary APIs |
|------|------|--------------|
| Overview | `src/pages/Overview.tsx` | `/api/dashboard/overview` |
| Visibility | `src/pages/Visibility.tsx` | `/api/visibility/*`, `/api/capture/pcap` |
| Detection | `src/pages/Detection.tsx` | `/api/detection/status`, `scan`, `inference-preview` |
| Alerts | `src/pages/Alerts.tsx` | `/api/detection/alerts` |
| Forensics | `src/pages/Forensics.tsx` | `/api/forensics/*` |
| Assistant | `src/pages/Assistant.tsx` | `/api/forensics/chat` |
| Settings | `src/pages/Settings.tsx` | `/api/dashboard/config`, `stats`, `/api/demo/load-sample` |

---

## Demo / fallback (clearly separated)

| Purpose | Location |
|---------|----------|
| Synthetic PCAP for viva | `app/demo_assets.py`, `POST /api/demo/load-sample` |
| Auto-ingest on boot | `app/bootstrap.py` (`NETGUARD_AUTO_DEMO=1`) |
| Static UI-only numbers | `src/data/networkData.ts` (used when API unreachable) |
| Package marker | `demo/README.md` |

---

## Single entrypoints

- **API:** `app/main.py` → `run_backend.py`
- **UI:** `src/main.tsx` → `npm run dev`
