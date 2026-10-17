export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface PacketSummary {
  num: number;
  time: string;
  src: string;
  dst: string;
  src_port: number | null;
  dst_port: number | null;
  proto: string;
  protocol: string;
  length: number;
  info: string;
}

export interface Threat {
  id: number;
  rule_id: string;
  title: string;
  severity: Severity;
  mitre_id: string;
  mitre_tactic: string;
  src: string;
  dst: string;
  packet_count: number;
  packet_nums: number[];
  description: string;
  evidence: Record<string, unknown>;
}

export interface TopoNode {
  id: string;
  label: string;
  color: string;
  packets: number;
  threat_level: string;
  threat_score: number;
  is_private: boolean;
  country: string;
  isp: string;
  bytes: number;
}

export interface TopoLink {
  source: string;
  target: string;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface CatalogAttack {
  id: number;
  attack_id: string;
  name_en: string;
  name_ar: string;
  severity: Severity;
  mitre_id: string;
  mitre_tactic: string;
  category: string;
  detected: boolean;
  matched_packets_count: number;
  matched_packets: number[];
  mechanism: string;
  mitigation: string;
  rules: string | string[];
  evidence: string;
}

export interface GeoEntry {
  IP: string;
  Is_Private: boolean;
  Domain_Names: string[];
  Reverse_DNS: string;
  Country: string;
  Country_Code: string;
  City: string;
  ISP: string;
  ASN: string;
  Coordinates: string;
  Location_Summary: string;
}

export interface CarvedFile {
  File_ID: number;
  Filename: string;
  File_Type: string;
  Source_IP: string;
  Dest_IP: string;
  Protocol: string;
  Size_Bytes: number;
  Size_Formatted?: string;
  MD5: string;
  SHA256: string;
  Packet_Numbers?: number[];
}

export interface TimelineStep {
  Timestamp_Rel: string;
  Kill_Chain_Phase: string;
  Incident_Title: string;
  Severity: Severity;
  Attacker: string;
  Victim: string;
  MITRE_ID: string;
  Trigger_Packets: number[];
  Description: string;
}

export interface PlaybookStep {
  Step: number;
  Priority: string;
  Action: string;
  Target: string;
  Instructions: string;
  Rationale: string;
}

export interface IpProfile {
  IP: string;
  Total_Packets: number;
  Packets_Sent: number;
  Packets_Recv: number;
  Total_Bytes: number;
  Bytes_Sent: number;
  Bytes_Recv: number;
  Protocols: Record<string, number>;
  Ports_Count?: number;
  Peers_Count?: number;
  Threat_Score: number;
  Threat_Level: string;
  Associated_Alerts: string[];
}

export interface StreamRow {
  Stream_ID: string;
  Protocol: string;
  Client: string;
  Server: string;
  Packet_Count: number;
  Total_Bytes: number;
  Duration_Seconds: number;
  Client_Payload_Preview: string;
  Server_Payload_Preview: string;
}

export interface IntelLookup {
  Target: string;
  Type: string;
  Source?: string;
  Verdict: string;
  Detections?: string;
  Malicious_Count?: number;
  Suspicious_Count?: number;
  Harmless_Count?: number;
  Reputation_Score?: number;
  Country?: string;
  ASN?: string;
  Owner?: string;
}

export interface Defcon {
  level: number;
  title: string;
  posture: string;
  posture_color: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SummaryStats {
  Total_Packets: number;
  Total_Bytes: number;
  Total_Bytes_Formatted: string;
  Duration_Seconds: number;
  Avg_Packet_Size: number;
  Packet_Rate: string;
  Data_Rate_Kbps: string;
}

export interface ProtocolDist {
  Protocol: string;
  Count: number;
  Percentage: number;
}

export interface PacketDetail {
  found: boolean;
  num: number;
  length: number;
  rel_time: string;
  src: string;
  dst: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  info: string;
  layers: Record<string, unknown>[];
  hex_dump: string;
  ascii_text: string;
  raw_payload_text: string;
  entropy: number;
  is_high_entropy: boolean;
  decodings: { Type: string; Confidence: number; Result: string }[];
}

export interface StreamFollowResult {
  found: boolean;
  protocol: string;
  client: string;
  server: string;
  total_packets: number;
  duration: number;
  client_bytes: number;
  server_bytes: number;
  chunks_count: number;
  chunks: {
    direction: string;
    sender: string;
    receiver: string;
    packet_num: number;
    rel_time: string;
    text: string;
    hex: string;
  }[];
}

export interface IpInspection {
  ip: string;
  geo: GeoEntry;
  profile: IpProfile;
  defcon: { status: string; color: string; score: number; level: string };
  peers: {
    peer: string;
    packets_total: number;
    packets_tx: number;
    packets_rx: number;
    bytes_total: number;
    bytes_fmt: string;
    protocols: string[];
  }[];
  port_footprint: { port: number; protocol: string; role: string; count: number }[];
  threats: (Pick<Threat, "rule_id" | "title" | "severity" | "mitre_id" | "mitre_tactic"> & {
    role: string;
    description: string;
    packet_nums: number[];
  })[];
  vt: IntelLookup;
  carved: CarvedFile[];
}

export interface Grounding4Q {
  has_incident: boolean;
  summary?: string;
  defcon?: string;
  q1_what?: {
    attack_type?: string;
    mitre_technique?: string;
    mitre_tactic?: string;
    confidence?: number;
    indicators?: string[];
  };
  q2_who?: {
    source_ip?: string;
    actor_type?: string;
    targets?: string[];
    target_ports?: number;
  };
  q3_when?: {
    start_time?: string;
    end_time?: string;
    duration_seconds?: number;
    total_flows?: number;
  };
  q4_status?: {
    status?: string;
    priority?: string;
    recommended_action?: string;
    action_plan?: string[];
  };
  narrative?: string;
  containment_command?: string;
}

export interface AiData {
  has_data: boolean;
  error?: string;
  total_flows: number;
  attack_count: number;
  suspicious_count: number;
  normal_count: number;
  attack_pct: number;
  ip_summaries: Record<string, unknown>[];
  grounding_4q: Grounding4Q;
  incidents: Record<string, unknown>[];
  dns_telemetry: Record<string, unknown>[];
  tls_telemetry: Record<string, unknown>[];
  beaconing: Record<string, unknown>[];
  hierarchical_tree: Record<string, unknown>[];
  active_mitre_tids: string[];
  evidence_hashes: { sha256: string; md5: string };
  vector_map: { attackers: string[]; targets: string[]; benign: string[]; links: { source: string; target: string; decision: string; count: number }[] };
  velocity_timeline: { time: string; attack: number; suspicious: number; normal: number }[];
  matrix_tactics: { name: string; sub: string; techniques: { id: string; name: string }[] }[];
  cti_summary: Record<string, unknown>;
  anomaly_hist: { bin: number; count: number }[];
  presets: { id: string; name: string; description: string; full_path?: string }[];
}

export interface Summary {
  has_data: boolean;
  job_id: string;
  filename: string;
  total_packets: number;
  summary_stats: SummaryStats;
  protocol_dist: ProtocolDist[];
  defcon: Defcon;
  hud: Record<string, unknown>;
  threats: Threat[];
  topology: { nodes: TopoNode[]; links: TopoLink[] };
  catalog: CatalogAttack[];
  geo: GeoEntry[];
  carved: CarvedFile[];
  timeline: TimelineStep[];
  playbook: PlaybookStep[];
  ip_profiles: IpProfile[];
  streams: StreamRow[];
  intel: { public_ips: IntelLookup[]; domains: IntelLookup[]; saved_key: string };
  ai_data?: AiData;
}

export interface TimelineSeries {
  bucket_seconds: number;
  series: { t: number; packets: number; bytes: number }[];
  markers: {
    time: number;
    end_time: number;
    rule_id: string;
    title: string;
    severity: Severity;
    mitre_id: string;
    src: string;
    dst: string;
    packet_count: number;
  }[];
}

export interface JobSnapshot {
  job_id: string;
  filename: string;
  status: "pending" | "running" | "done" | "error";
  error: string | null;
  progress: { stage: string; pct: number; label: string }[];
}
