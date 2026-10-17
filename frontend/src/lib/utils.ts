import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFO: "#64748b",
};

// Single source of truth for client→/server← stream coloring (dissector + streams pages)
export const STREAM_TEXT = {
  client: "text-cyan-600 dark:text-cyan-300",
  server: "text-indigo-600 dark:text-indigo-300",
} as const;

export const STREAM_BG = {
  client: "bg-cyan-500/10 text-cyan-600 dark:text-cyan-300",
  server: "bg-indigo-500/10 text-indigo-600 dark:text-indigo-300",
} as const;

export function formatBytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4);
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}
