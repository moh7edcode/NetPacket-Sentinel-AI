import { useTranslation } from "react-i18next";
import { FileSearch } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AiData } from "@/services/types";

function str(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.map(String).join(", ");
  return String(v);
}

export function FourQCard({ ai }: { ai?: AiData }) {
  const { t } = useTranslation();
  const g = ai?.grounding_4q;

  if (!g || !g.has_incident) {
    return (
      <Card className="h-full">
        <CardHeader className="pb-1">
          <CardTitle className="flex items-center gap-2">
            <FileSearch className="h-4 w-4 text-primary dark:animate-pulse-glow" />
            {t("dashboard.fourq")}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-3 pt-1 text-[12px] text-muted-foreground">
          {g?.summary || "Run an analysis to generate the automated incident storyline."}
        </CardContent>
      </Card>
    );
  }

  const q1 = g.q1_what ?? {};
  const q2 = g.q2_who ?? {};
  const q3 = g.q3_when ?? {};
  const q4 = g.q4_status ?? {};

  const rows = [
    {
      q: t("dashboard.q2"),
      a: str(q1.attack_type),
      sub: [
        str(q1.mitre_technique),
        q1.confidence !== undefined ? `${t("dashboard.confidence")}: ${q1.confidence}%` : "",
      ].filter(Boolean),
    },
    {
      q: t("dashboard.q1"),
      a: [str(q2.source_ip), str(q2.actor_type)].filter(Boolean).join(" — "),
      sub: [
        q2.targets?.length ? `${t("dashboard.targets")}: ${q2.targets.slice(0, 3).join(", ")}` : "",
      ].filter(Boolean),
    },
    {
      q: t("dashboard.q3"),
      a: `${str(q3.start_time)} → ${str(q3.end_time)}`,
      sub: [
        q3.duration_seconds !== undefined ? `${q3.duration_seconds.toFixed(1)}s` : "",
        q3.total_flows !== undefined ? `${q3.total_flows} ${t("dashboard.flows")}` : "",
      ].filter(Boolean),
    },
    {
      q: t("dashboard.q4"),
      a: str(q4.status),
      sub: [str(q4.priority), str(q4.recommended_action)].filter(Boolean),
    },
  ];

  return (
    <Card className="h-full">
      <CardHeader className="pb-1">
        <CardTitle className="flex items-center gap-2">
          <FileSearch className="h-4 w-4 text-primary dark:animate-pulse-glow" />
          {t("dashboard.fourq")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 p-3 pt-1">
        {rows.map((r, i) => (
          <div key={i} className="rounded-md border bg-muted/40 p-2">
            <div className="text-[10px] font-bold uppercase tracking-wider text-primary">{r.q}</div>
            <div className="mt-0.5 text-[12px] font-medium leading-snug">{r.a || "—"}</div>
            {r.sub.length > 0 && (
              <div className="mt-0.5 space-y-0.5">
                {r.sub.map((s, j) => (
                  <div key={j} className="text-[11px] leading-snug text-muted-foreground">
                    {s}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
        {g.narrative && (
          <div className="border-t pt-2 text-[11px] italic leading-snug text-muted-foreground">
            {g.narrative}
          </div>
        )}
        {g.containment_command && (
          <div className="rounded-md border border-threat/40 bg-threat/10 p-2">
            <code className="mono break-all text-[10px] text-threat">{g.containment_command}</code>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
