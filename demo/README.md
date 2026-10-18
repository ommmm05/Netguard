# `demo/` — Viva & offline presentation layer

This folder **does not** implement capture or ML logic. It exists so the ZIP clearly separates:

| Area | Path |
|------|------|
| **Production-style pipeline** | `capture/`, `visibility/`, `detection/`, `forensics/`, `app/routers/` |
| **Synthetic PCAP + auto-run** | `app/demo_assets.py`, `app/bootstrap.py`, `POST /api/demo/load-sample` |
| **Dashboard mock rows** | `src/data/networkData.ts` (only when the FastAPI backend is down) |

For report alignment, see `docs/BLUEPRINT.md`.
