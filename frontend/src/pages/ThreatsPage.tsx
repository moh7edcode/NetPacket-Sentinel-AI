import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ShieldAlert } from "lucide-react";
import { api } from "@/services/api";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { Severity } from "@/services/types";

function AlertsList() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const focus = params.get("alert");
  const [sev, setSev] = useState<string>("ALL");
  const { data: threats } = useQuery({ queryKey: ["threats"], queryFn: api.threats });
  const filtered = (threats ?? []).filter((th) => sev === "ALL" || th.severity === sev);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">{t("common.severity")}</span>
        <Select value={sev} onValueChange={setSev}>
          <SelectTrigger className="h-8 w-36"><SelectValue /></SelectTrigger>
          <SelectContent>
            {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
              <SelectItem key={s} value={s}>{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {filtered.map((th) => (
        <Card key={th.id} className={focus === String(th.id) ? "ring-2 ring-primary" : ""} id={`alert-${th.id}`}>
          <CardContent className="flex flex-col gap-2 p-3 sm:flex-row sm:items-start">
            <div className="w-fit rounded-md border-l-4 bg-muted/40 p-2" style={{ borderLeftColor: SEVERITY_COLORS[th.severity] }}>
              <SeverityBadge severity={th.severity} />
              <div className="mono mt-1 text-[10px] text-muted-foreground">{th.rule_id}</div>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-semibold">{th.title}</span>
                <span className="mono rounded bg-accent/40 px-1.5 text-[10px]">{th.mitre_id} · {th.mitre_tactic}</span>
              </div>
              <div className="mono text-[11px] text-muted-foreground">{th.src} → {th.dst} · {th.packet_count} {t("common.packets")}</div>
              <p className="mt-1 text-xs leading-snug">{th.description}</p>
              {Object.keys(th.evidence ?? {}).length > 0 && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-[11px] text-primary">{t("threats.storyline")}: {t("common.rule")}</summary>
                  <pre className="mono mt-1 max-h-40 overflow-auto rounded border bg-muted/30 p-2 text-[10px]">
                    {JSON.stringify(th.evidence, null, 2)}
                  </pre>
                </details>
              )}
            </div>
            <Link to="/dissector" className="mono self-start text-[10px] text-primary hover:underline"
              title={th.packet_nums.join(", ")}>
              #{th.packet_nums[0]}… → {t("nav.dissector")}
            </Link>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function AttackMatrix() {
  const { t } = useTranslation();
  const { data: ai } = useQuery({ queryKey: ["ai"], queryFn: api.ai });
  const { data: threats } = useQuery({ queryKey: ["threats"], queryFn: api.threats });
  const hits = useMemo(() => {
    const m = new Map<string, number>();
    threats?.forEach((th) => {
      const id = th.mitre_id?.split(".")[0];
      if (id) m.set(id, (m.get(id) ?? 0) + 1);
    });
    return m;
  }, [threats]);
  const tactics = ai?.matrix_tactics ?? [];
  const max = Math.max(1, ...hits.values());

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle>{t("threats.matrix")}</CardTitle>
      </CardHeader>
      <CardContent className="grid grid-flow-col auto-cols-[minmax(120px,1fr)] gap-2 overflow-x-auto">
        {tactics.map((tac) => (
          <div key={tac.sub} className="rounded-md border">
            <div className="border-b bg-muted/50 px-2 py-1 text-[10px] font-bold uppercase">{tac.name} <span className="mono text-muted-foreground">{tac.sub}</span></div>
            <div className="space-y-1 p-1.5">
              {tac.techniques.map((tk, i) => {
                const n = hits.get(tk.id.split(".")[0]) ?? 0;
                const intensity = n / max;
                return (
                  <div key={i} className="rounded px-2 py-1.5 text-[10px]"
                    style={n ? { backgroundColor: `rgba(239,68,68,${0.12 + intensity * 0.55})`, boxShadow: "0 0 8px rgba(239,68,68,.3)" } : { backgroundColor: "hsl(var(--muted))", opacity: 0.7 }}>
                    <span className="mono font-semibold">{tk.id}</span> {tk.name}
                    {n > 0 && <span className="ms-1 font-bold text-threat">×{n}</span>}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function Storyline() {
  const { t } = useTranslation();
  const { data: tl } = useQuery({ queryKey: ["timeline"], queryFn: api.attackTimeline });
  return (
    <Card>
      <CardHeader className="pb-2"><CardTitle>{t("threats.storyline")}</CardTitle></CardHeader>
      <CardContent className="space-y-2">
        {(tl ?? []).map((s, i) => (
          <div key={i} className="flex gap-3 rounded-md border bg-muted/30 p-2.5">
            <div className="mono w-20 shrink-0 text-[11px] text-muted-foreground">t+{s.Timestamp_Rel}s</div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={s.Severity} />
                <span className="text-[10px] uppercase text-primary">{s.Kill_Chain_Phase}</span>
                <span className="mono text-[10px] text-muted-foreground">{s.MITRE_ID}</span>
              </div>
              <div className="text-sm font-medium">{s.Incident_Title}</div>
              <div className="mono text-[11px] text-muted-foreground">{s.Attacker} → {s.Victim}</div>
              <p className="mt-0.5 text-xs">{s.Description}</p>
              <div className="mono mt-1 text-[10px] text-muted-foreground">
                {t("encyclopedia_page.triggered_packets")}: {s.Trigger_Packets.slice(0, 10).join(", ")}
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export default function ThreatsPage() {
  const { t } = useTranslation();
  const { data: threats } = useQuery({ queryKey: ["threats"], queryFn: api.threats });
  return (
    <div>
      <PageHeader icon={ShieldAlert} title={t("nav.threats")} count={threats?.length ?? 0} />
      <Tabs defaultValue="alerts">
        <TabsList>
          <TabsTrigger value="alerts">{t("threats.title")}</TabsTrigger>
          <TabsTrigger value="matrix">{t("threats.matrix")}</TabsTrigger>
          <TabsTrigger value="story">{t("threats.storyline")}</TabsTrigger>
        </TabsList>
        <TabsContent value="alerts"><AlertsList /></TabsContent>
        <TabsContent value="matrix"><AttackMatrix /></TabsContent>
        <TabsContent value="story"><Storyline /></TabsContent>
      </Tabs>
    </div>
  );
}
