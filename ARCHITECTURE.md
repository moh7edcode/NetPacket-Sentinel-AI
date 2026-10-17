# NetPacket-Sentinel-AI — Web Architecture

Conversion of the pywebview desktop app (`app_gui.py`, embedded single-string UI) into a
decoupled **React SPA** + **FastAPI** web application. The Python analysis engine is
wrapped, **not modified**.

```
final/
├── backend/            FastAPI layer (NEW — REST + WebSocket only)
│   ├── main.py         App factory, CORS, router + WS mount, engine path bootstrap
│   ├── sessions.py     SessionManager: jobs, active session, thread-safe state
│   ├── pipeline.py     Mirrors CyberBridgeAPI._process_pcap_file / run_ai_analysis
│   ├── api.py          All /api/* endpoints (one per bridge method)
│   ├── ws.py           /ws/progress/{job_id} live progress streaming
│   └── serializers.py  Bytes/object → JSON (StreamChunk, CarvedFile, catalog…)
├── frontend/           React 18 + TypeScript + Vite SPA (NEW)
│   └── src/
│       ├── services/api.ts      Single typed API client (fetch + WS)
│       ├── hooks/               useAnalysisJob, useProgress, query hooks
│       ├── i18n/                i18next: en.json (default) + ar.json (RTL)
│       ├── components/ui/       shadcn-style primitives (Button, Card, Badge, Tabs, Dialog…)
│       ├── components/layout/   AppShell, Sidebar, TopBar (theme + language switchers)
│       ├── components/dashboard/ KPI row, timeline, donut, threat panel, AI panel,
│       │                        MITRE heat matrix, topology mini-map, 4Q card, IOC strip
│       ├── components/topology/ d3-force graph (shared by mini-map + full page)
│       └── pages/               Dashboard, Dissector, Threats, Topology, Streams,
│                                Carved, Encyclopedia, Triage, Reports
├── *.py (engine)       pcap_parser, analyzer, threat_detector, ai_engine, stream_follower,
│                       file_carver, payload_decoder, threat_intel, geo_resolver,
│                       network_attacks_catalog, ai_triage_playbook, exporter,
│                       dashboard_generator, stream_profiler, config_manager  ← UNTOUCHED
└── app_gui.py          Legacy desktop app kept as reference; no longer the primary UI
```

## Backend design

- **Job-based analysis.** `POST /api/pcap/upload` stores the file, spawns a background
  thread running the full pipeline (parse → analyze → threats → streams → catalog → geo →
  carve → timeline/playbook → intel → AI pre-warm), and returns `job_id`.
  `WS /ws/progress/{job_id}` streams stage events: `{job_id, stage, pct, label, done, error?}`.
- **Sessions.** Each completed job becomes an `AnalysisSession` holding the same cached
  state the desktop bridge held (`all_packets`, `detected_alerts`, `cached_payload`,
  `cached_ai_results`, profiler, carver, geo, catalog, timeline, playbook, intel engine).
  Endpoints operate on the **active session** (latest finished job); `?job=` overrides.
- **Stateless engine calls.** All engine modules are imported as-is from the repo root
  (`sys.path` bootstrap in `main.py`). CPU-bound calls run in a threadpool
  (`fastapi` `run_in_threadpool` / `def` endpoints).
- **AI models.** `AISentinelEngine.get_instance().load_models_lazy()` loads ~130 MB of
  joblib pickles from `models/` on first AI request (lazy singleton, same as desktop).
  If model files are missing, `/api/ai` returns `has_data:false + error` — the UI
  degrades gracefully.
- **Network side effects preserved but bounded.** `threat_intel` hits VirusTotal only when
  a key is set (`inspector_config.json` / `VIRUSTOTAL_API_KEY`); `geo_resolver` attempts
  ip-api.com for non-builtin public IPs with a 3 s timeout and offline fallback.
- **Reports.** `POST /api/report/generate {format}` writes to `backend/exports/` and
  returns a download URL (replaces the desktop save dialogs). Carved files and containment
  scripts are served the same way.

### API contract (mirror of CyberBridgeAPI)

| Bridge method | Endpoint |
|---|---|
| `load_pcap / open_file_dialog` | `POST /api/pcap/upload`, `POST /api/pcap/local {path}` |
| `get_initial_data` | `GET /api/session` + `GET /api/summary` |
| `get_packets(offset,limit)` | `GET /api/packets?offset&limit&q=` |
| `inspect_packet(id)` | `GET /api/packets/{num}` |
| `follow_stream(id)` | `GET /api/streams/follow/{num}` |
| `inspect_ip(ip)` | `GET /api/ip/{ip}` |
| `lookup_vt_deep` | `GET /api/intel/{target}?kind=ip\|domain` |
| `save_carved_file(id)` | `GET /api/carved/{id}/download` |
| `export_report(fmt)` | `POST /api/report/generate {format}` |
| `save_vt_key / get_vt_key` | `PUT/GET /api/config/vt-key` |
| `decode_payload_raw` | `POST /api/decoder {input,is_hex}` |
| `run_ai_analysis / get_ai_data` | `GET /api/ai` (cache + on-demand) |
| `simulate_sandbox` | `POST /api/ai/sandbox` |
| `get_ai_benchmarks` | `GET /api/ai/benchmarks` |
| `get_preset_scenarios` | `GET /api/ai/presets` |
| `load_preset_scenario(id)` | `POST /api/ai/presets/{id}/load` |
| `export_containment_script` | `POST /api/blocklist/generate` |
| (payload sections) | `GET /api/threats /topology /catalog /geo /carved /timeline /playbook /streams /ip-profiles /hud` |
| (new, dashboard) | `GET /api/timeline/series` — per-second packets/bytes buckets + alert markers |

## Frontend design

- **Stack.** React 18 + TS + Vite; Tailwind + shadcn-style primitives + lucide-react;
  TanStack Query (server state, per-endpoint hooks) + React Router; Recharts (timeline,
  donut, anomaly histogram); d3-force on SVG (topology + AI vector map); Framer Motion
  (subtle), sonner-style toasts; `@tanstack/react-virtual` for packet tables.
- **Theme.** Light/white enterprise theme is the DEFAULT (first load, `next-themes`
  `defaultTheme="light"`); topbar toggle switches instantly to tactical cyber dark
  (`#0a0e17`, backdrop-blur glass cards, cyan `#22d3ee` / indigo `#6366f1`, red for
  threats, amber warnings). All colors are CSS variables — no reload.
- **Fonts.** Inter / Space Grotesk for UI; JetBrains Mono for hex dumps, packet data,
  filter bar, stream view.
- **i18n.** `i18next` + `react-i18next`, EN default, full AR bundle; switching to Arabic
  flips `dir="rtl"` on `<html>` and Tailwind logical properties mirror the layout.
  Switcher lives in the topbar next to the theme toggle.
- **Dashboard = one comprehensive page** (upload dropzone when idle; full results grid
  when a job completes): KPI hero row + DEFCON gauge, traffic timeline with alert
  markers, protocol donut + top talkers, threat summary, hybrid-AI panel, MITRE heat
  matrix, topology mini-map, Forensic 4Q card, IOC reputation strip. Every panel links
  to its drill-down page.
- **Dissector.** 3-pane Wireshark layout: virtualized table (server pagination + client
  display-filter syntax subset: `ip.addr=`, `tcp.port=`, `proto==`, `contains`),
  collapsible protocol tree, hex dump with entropy meter.
- **Dev wiring.** Vite proxies `/api` and `/ws` → `http://localhost:8000`.

## Run

```bash
# Backend
pip install fastapi "uvicorn[standard]" python-multipart pandas numpy scikit-learn joblib
uvicorn backend.main:app --reload --port 8000

# Frontend
cd frontend && npm install && npm run dev    # http://localhost:5173
```

## Phasing

1. Backend API (complete bridge parity) — `backend/`
2. Layout + theming + i18n shell — `frontend/src`
3. Main Dashboard — `pages/DashboardPage.tsx`
4. Packet Dissector — `pages/DissectorPage.tsx`
5. Secondary pages: Threats/MITRE, Topology, Streams & Payloads, Carved Files,
   Encyclopedia, AI Triage, Reports
