import type {
  AiData,
  CarvedFile,
  CatalogAttack,
  Defcon,
  GeoEntry,
  IntelLookup,
  IpInspection,
  IpProfile,
  JobSnapshot,
  PacketDetail,
  PacketSummary,
  PlaybookStep,
  ProtocolDist,
  Severity,
  StreamFollowResult,
  StreamRow,
  Summary,
  SummaryStats,
  Threat,
  TimelineSeries,
  TimelineStep,
  TopoLink,
  TopoNode,
} from "./types";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body);
    } catch {
      /* keep statusText */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  health: () => request<{ status: string }>("/api/health"),

  uploadPcap: (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    return request<{ job_id: string }>("/api/pcap/upload", { method: "POST", body: fd });
  },
  loadLocal: (path: string) =>
    request<{ job_id: string }>("/api/pcap/local", { method: "POST", ...json({ path }) }),
  job: (id: string) => request<JobSnapshot>(`/api/jobs/${id}`),
  session: () =>
    request<{ has_data: boolean; message?: string } & Partial<JobSnapshot>>("/api/session"),

  summary: () => request<Summary>("/api/summary"),
  packets: (offset = 0, limit = 500, q = "") =>
    request<{ total_packets: number; offset: number; limit: number; packets: PacketSummary[] }>(
      `/api/packets?offset=${offset}&limit=${limit}&q=${encodeURIComponent(q)}`,
    ),
  packet: (num: number) => request<PacketDetail>(`/api/packets/${num}`),
  followStream: (num: number) => request<StreamFollowResult>(`/api/streams/follow/${num}`),
  ip: (addr: string) => request<IpInspection>(`/api/ip/${encodeURIComponent(addr)}`),
  timelineSeries: () => request<TimelineSeries>("/api/timeline/series"),

  threats: () => request<Threat[]>("/api/threats"),
  topology: () => request<{ nodes: TopoNode[]; links: TopoLink[] }>("/api/topology"),
  catalog: () => request<CatalogAttack[]>("/api/catalog"),
  geo: () => request<GeoEntry[]>("/api/geo"),
  carved: () => request<CarvedFile[]>("/api/carved"),
  attackTimeline: () => request<TimelineStep[]>("/api/timeline"),
  playbook: () => request<PlaybookStep[]>("/api/playbook"),
  ipProfiles: () => request<IpProfile[]>("/api/ip-profiles"),
  streams: () => request<StreamRow[]>("/api/streams-list"),
  defcon: () => request<Defcon>("/api/defcon"),
  protocolDist: () => request<{ protocol_dist: ProtocolDist[]; summary_stats: SummaryStats }>(
    "/api/protocol-distribution",
  ),

  intel: (target: string, kind: "ip" | "domain" = "ip") =>
    request<IntelLookup>(`/api/intel/${encodeURIComponent(target)}?kind=${kind}`),

  vtKey: () => request<{ api_key: string }>("/api/config/vt-key"),
  setVtKey: (key: string) =>
    request<{ success: boolean }>("/api/config/vt-key", { method: "PUT", ...json({ api_key: key }) }),

  decode: (input_text: string, is_hex = false) =>
    request<{ success: boolean; entropy?: number; is_high_entropy?: boolean; decodings?: { Type: string; Confidence: number; Result: string }[]; error?: string }>(
      "/api/decoder",
      { method: "POST", ...json({ input_text, is_hex }) },
    ),

  ai: () => request<AiData>("/api/ai"),
  aiSandbox: (params: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/ai/sandbox", { method: "POST", ...json({ params }) }),
  aiBenchmarks: () => request<{ benchmark: Record<string, unknown>; viva_guide: { question: string; answer: string }[] }>(
      "/api/ai/benchmarks",
    ),
  presets: () => request<{ presets: { id: string; name: string; description: string }[] }>("/api/ai/presets"),
  loadPreset: (id: string) =>
    request<{ job_id: string }>(`/api/ai/presets/${encodeURIComponent(id)}/load`, { method: "POST" }),

  downloadCarvedUrl: (id: number) => `/api/carved/${id}/download`,
  reportGenerate: (format: "html" | "json" | "csv" | "dashboard") =>
    request<{ success: boolean; format: string; filename: string; download_url: string }>(
      "/api/report/generate",
      { method: "POST", ...json({ format }) },
    ),
  blocklistGenerate: (attacker_ip: string, attack_type = "Hostile Intrusion", mitre_id = "T1498") =>
    request<{ success: boolean; playbook: Record<string, string>; download_url: string }>(
      "/api/blocklist/generate",
      { method: "POST", ...json({ attacker_ip, attack_type, mitre_id }) },
    ),
};

export function progressSocketUrl(jobId: string): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/ws/progress/${jobId}`;
}

export type { Severity };
