import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, progressSocketUrl } from "@/services/api";
import type { JobSnapshot } from "@/services/types";

export interface ProgressState {
  pct: number;
  label: string;
  status: "idle" | "pending" | "running" | "done" | "error";
  error?: string;
}

export function useAnalysisSession() {
  return useQuery({
    queryKey: ["session"],
    queryFn: api.session,
    staleTime: 30_000,
  });
}

export function useSummary(enabled: boolean) {
  return useQuery({
    queryKey: ["summary"],
    queryFn: api.summary,
    enabled,
  });
}

export function useProgress(jobId: string | null) {
  const [state, setState] = useState<ProgressState>({ pct: 0, label: "", status: "idle" });
  const qc = useQueryClient();
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!jobId) return;
    setState({ pct: 0, label: "Connecting…", status: "running" });
    let stopped = false;
    const socket = new WebSocket(progressSocketUrl(jobId));
    wsRef.current = socket;
    socket.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (stopped) return;
      if (msg.type === "progress") {
        setState({ pct: msg.pct, label: msg.label, status: "running" });
      } else if (msg.type === "complete") {
        setState((s) => ({ ...s, status: msg.status, pct: 100, error: msg.error ?? undefined }));
        if (msg.status === "done") {
          qc.invalidateQueries({ queryKey: ["session"] });
          qc.invalidateQueries({ queryKey: ["summary"] });
          ["threats", "topology", "catalog", "geo", "carved", "timeline", "playbook",
           "ip-profiles", "streams-list", "timeline-series", "ai"].forEach((k) =>
            qc.invalidateQueries({ queryKey: [k] }));
        }
      } else if (msg.type === "error") {
        setState((s) => ({ ...s, status: "error", error: msg.error }));
      }
    };
    socket.onerror = () => setState((s) => ({ ...s, status: "error", error: "Progress stream failed" }));
    const poll = setInterval(async () => {
      if (stopped) return;
      try {
        const snap: JobSnapshot = await api.job(jobId);
        if (snap.status === "done" || snap.status === "error") {
          stopped = true;
          socket.close();
          setState((s) => ({
            pct: 100,
            label: snap.status,
            status: snap.status,
            error: snap.error ?? undefined,
          }));
          if (snap.status === "done") {
            qc.invalidateQueries({ queryKey: ["session"] });
            qc.invalidateQueries({ queryKey: ["summary"] });
          }
        }
      } catch {
        /* transient */
      }
    }, 1500);
    return () => {
      stopped = true;
      clearInterval(poll);
      socket.close();
    };
  }, [jobId, qc]);

  return state;
}

export function useUpload() {
  return useMutation({ mutationFn: (file: File) => api.uploadPcap(file) });
}

export function useLoadPreset() {
  return useMutation({ mutationFn: (id: string) => api.loadPreset(id) });
}
