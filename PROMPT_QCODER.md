# UI Conversion Prompt — NetPacket-Sentinel-AI

Copy everything after the divider below and paste it into QCoder:

---

You are an expert frontend engineer. You are working on "NetPacket-Sentinel-AI" — a network packet forensics (PCAP) and incident response (DFIR) platform currently built as a pywebview desktop app, where the entire UI (HTML/CSS/JS) is embedded as a single string inside `app_gui.py` (8,660 lines). Your task: rebuild the UI as a fully modern, professional web application with complete separation between the frontend and the Python analysis engine.

## Goal

Convert the UI into a modern SPA using the following stack:

- React 18 + TypeScript + Vite
- Tailwind CSS + shadcn/ui + lucide-react for icons
- TanStack Query for data/state management + React Router for navigation
- Recharts / ECharts for charts, react-flow or D3 force graph for network topology
- FastAPI (Python) as the backend API layer wrapping the existing engine modules as-is (`pcap_reader`, `analyzer`, `threat_detector`, `ai_engine`, `stream_follower`, `file_carver`, `payload_decoder`, `threat_intel`, `geo_resolver`, `network_attacks_catalog`, `ai_triage_playbook`, `exporter`) — **do NOT modify the engine logic**; only write an API layer on top (REST endpoints + WebSocket for live analysis progress).

## Language & Theming (critical requirements)

- **Primary language: English.** All UI text, labels, tooltips, and reports render in English by default.
- **Language switcher with Arabic option:** a clean i18n system (i18next or equivalent) with EN as default and a full Arabic translation (with proper RTL layout flipping when Arabic is selected). The switcher must live in the top bar.
- **Primary theme: Light (White) mode** — a crisp, professional, enterprise-grade light theme (white/slate backgrounds, subtle shadows, clean borders) as the DEFAULT theme on first load.
- **Dark mode toggle** in the top bar, switching instantly to a tactical "Cyber" dark theme (deep navy `#0a0e17` background, glassmorphism cards with backdrop-blur, neon accents: Cyan `#22d3ee`, Indigo `#6366f1`, Red `#ef4444` for threats, Amber for warnings). Use `next-themes` (or equivalent) with no page reload.
- Fonts: Inter or Space Grotesk for text, JetBrains Mono / IBM Plex Mono for code, hex dumps, and packet data.
- Smooth transitions (framer-motion) without excess, skeleton loaders, and toast notifications for actions.
- The system logo exists in `assets/` — use it in the sidebar/header.

## Main Dashboard (the centerpiece — build this as ONE comprehensive results page)

Build a **single unified Analysis Dashboard** that, after a PCAP is analyzed, shows ALL results at once — no hunting across tabs for the summary. It must include:

1. **KPI Hero Row:** animated stat cards — total packets, total volume, duration, transfer rate, active conversations, unique IPs, and current DEFCON/threat level with a color-coded severity gauge.
2. **Traffic Timeline:** interactive time-series chart of packets/bytes per second with alert markers overlaid (hovering an alert shows the threat details).
3. **Protocol Distribution:** donut/stacked chart of protocol breakdown (TCP/UDP/ICMP/ARP/DNS/HTTP/TLS...) + top talkers table (source/destination pairs by volume).
4. **Threat Summary Panel:** count of detected threats by severity (Critical/High/Medium/Low), latest alerts feed with severity badges, and each alert links to its full detail.
5. **AI Engine Panel:** hybrid ML engine results — Random Forest classification summary, Isolation Forest anomaly score distribution, flagged zero-day outliers, and model confidence indicators.
6. **MITRE ATT&CK Overview:** condensed heat-mapped matrix showing which techniques were detected, glowing on hits, linking to the full matrix view.
7. **Topology Mini-Map:** a compact live force-directed graph of the network with color-coded nodes (safe/suspicious/malicious), expandable to the full Topology page.
8. **Forensic 4Q Card:** the automated answers to the four forensic questions (Who attacked? What happened? When? How?) rendered as an executive incident storyline.
9. **IOC & Reputation Strip:** top Indicators of Compromise with VirusTotal reputation badges and geo/ASN flags.

## Secondary Pages (drill-down views)

1. **Packet Dissector (3-pane Wireshark-style):** virtualized packet table with pagination, collapsible protocol tree, hex dump with byte-entropy indicator, advanced display filters (Wireshark-like syntax), per-protocol row coloring.
2. **Threats & MITRE ATT&CK (full):** full alert list with severity filtering, complete MITRE ATT&CK v16 matrix, incident storyline detail view.
3. **Live Topology (full):** interactive force-directed graph with animated packet pulses, node drill-down modal on click (peers, port fingerprint, Geo/ASN, VirusTotal, carved files).
4. **Streams & Payloads:** bidirectional TCP/HTTP stream reassembly with client/server color coding, payload de-obfuscation (Base64/Hex/URL/Gzip/XOR) with an interactive Shannon Entropy sandbox.
5. **Carved Files:** gallery of files extracted from traffic with SHA-256/MD5 hashes and disk export.
6. **Attacks Encyclopedia:** searchable network attacks catalog, each attack linked to the packets that triggered it.
7. **AI Triage & Response:** automated response recommendations, one-click generation of block rules (iptables / PowerShell) with copy button.
8. **Reports:** generate and download HTML/JSON/CSV reports + Executive Report preview.

## API Backend (FastAPI)

- `POST /api/pcap/upload` → starts analysis (returns job_id) with `WS /ws/progress` streaming live progress.
- `GET /api/packets?offset&limit&filter` → paginated packets.
- `GET /api/packets/{id}` → protocol tree + hex dump.
- `GET /api/summary` , `GET /api/threats` , `GET /api/ai/results` , `GET /api/streams` , `GET /api/files` , `GET /api/topology` , `GET /api/geo/{ip}` , `GET /api/intel/{ioc}` , `POST /api/report/generate` , `POST /api/blocklist/generate`.
- **The precise reference for existing logic: the `CyberBridgeAPI` class in `app_gui.py`** — mirror its method signatures as endpoints so no feature is lost.

## Quality Constraints

- Do not lose ANY feature present in `app_gui.py` — review it feature by feature before starting.
- Clean code structure: `components/` , `pages/` , `hooks/` , a single centralized `services/api.ts`, and `i18n/` for translations.
- Virtualized tables for performance (PCAP files with tens of thousands of packets).
- Start with an `ARCHITECTURE.md` explaining the structure, then implement in phases: Backend API → Layout & theming → Main Dashboard → Dissector → remaining pages.
- Provide a run README: `uvicorn` for the backend, `npm run dev` for the frontend.
