import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Brain, ClipboardCopy, Cpu, Download, FlaskConical, ScrollText, ShieldX } from "lucide-react";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SeverityBadge } from "@/components/SeverityBadge";
import { cn } from "@/lib/utils";
import { BenchmarksCard } from "@/components/triage/BenchmarksCard";
import { CtiCard } from "@/components/triage/CtiCard";
import { IncidentsTable } from "@/components/triage/IncidentsTable";
import type { AiData } from "@/services/types";

function CopyBlock({ title, code }: { title: string; code: string }) {
  const { t } = useTranslation();
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{title}</span>
        <Button size="sm" variant="ghost"
          onClick={() => { navigator.clipboard.writeText(code); toast.success(t("triage_page.copied")); }}>
          <ClipboardCopy className="h-3.5 w-3.5" /> {t("triage_page.copy")}
        </Button>
      </div>
      <pre className="mono overflow-x-auto rounded-md border bg-muted/40 p-2 text-[11px] leading-relaxed">{code}</pre>
    </div>
  );
}

function BlockRules({ ip, ai }: { ip: string; ai?: AiData }) {
  const { t } = useTranslation();
  const [attackType, setAttackType] = useState("Hostile Intrusion");
  const [mitre, setMitre] = useState("T1498");
  const gen = useMutation({
    mutationFn: () => api.blocklistGenerate(ip, attackType, mitre),
    onSuccess: (d) => {
      toast.success(`Block rules generated for ${ip}`);
      return d;
    },
  });
  const [result, setResult] = useState<Awaited<ReturnType<typeof api.blocklistGenerate>> | null>(null);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm"><ShieldX className="h-4 w-4 text-primary" />Containment — {ip}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <Input value={attackType} onChange={(e) => setAttackType(e.target.value)} className="h-8 max-w-[220px] text-xs" />
          <Input value={mitre} onChange={(e) => setMitre(e.target.value)} className="h-8 w-24 text-xs" />
          <Button size="sm" onClick={async () => setResult(await gen.mutateAsync())}>{t("triage_page.block_iptables")}</Button>
          {result && (
            <Button size="sm" variant="outline" asChild>
              <a href={result.download_url} download><Download className="h-3.5 w-3.5" /> {t("triage_page.download_sh")}</a>
            </Button>
          )}
        </div>
        {result?.playbook?.iptables && <CopyBlock title={t("triage_page.block_iptables")} code={result.playbook.iptables} />}
        {result?.playbook?.powershell && <CopyBlock title={t("triage_page.block_powershell")} code={result.playbook.powershell} />}
        {ai?.cti_summary?.firewall_cmd && (
          <CopyBlock title="Recommended Edge Rule" code={ai.cti_summary.firewall_cmd} />
        )}
      </CardContent>
    </Card>
  );
}

function Sandbox() {
  const { t } = useTranslation();
  const [params, setParams] = useState<Record<string, string>>({
    protocol: "TCP",
    src_port: "443",
    dst_port: "80",
    flow_duration: "5",
    total_fwd_packets: "50",
    flow_bytes_s: "9000",
    flow_packets_s: "150",
  });
  const sim = useMutation({ mutationFn: (p: Record<string, unknown>) => api.aiSandbox(p) });
  const out = sim.data as Record<string, unknown> | undefined;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm"><FlaskConical className="h-4 w-4 text-primary" />{t("triage_page.sandbox")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
          {Object.entries(params).map(([k, v]) => (
            <div key={k}>
              <Label className="mono text-[9px] uppercase text-muted-foreground">{k}</Label>
              <Input className="mono h-7 text-[11px]" value={v} onChange={(e) => setParams({ ...params, [k]: e.target.value })} />
            </div>
          ))}
        </div>
        <Button size="sm" onClick={() => sim.mutate(params)} disabled={sim.isPending}>
          {sim.isPending ? "…" : t("triage_page.run_sim")}
        </Button>
        {out && !out.error && (
          <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/40 p-2 text-[11px]">
            <span>Decision: <b className="mono">{String(out.decision)}</b></span>
            <span>Severity: <SeverityBadge severity={String(out.severity ?? "INFO")} /></span>
            <span>Attack prob: <b className="mono">{Number(out.attack_probability ?? 0).toFixed(3)}</b></span>
            <span>Anomaly: <b className="mono">{Number(out.anomaly_score ?? 0).toFixed(3)}</b></span>
            <span className="col-span-2 text-muted-foreground">{String(out.reason ?? "")}</span>
          </div>
        )}
        {out?.error ? <div className="text-[11px] text-threat">{String(out.error)}</div> : null}
      </CardContent>
    </Card>
  );
}

export default function TriagePage() {
  const { t } = useTranslation();
  const { data: ai } = useQuery({ queryKey: ["ai"], queryFn: api.ai });
  const { data: playbook } = useQuery({ queryKey: ["playbook"], queryFn: api.playbook });
  const [blockIp, setBlockIp] = useState<string | null>(null);

  const malicious = (ai?.ip_summaries ?? []) as { ip: string; likely_type?: string; mitre?: { technique_id?: string } }[];

  return (
    <div>
      <PageHeader icon={Cpu} title={t("nav.triage")} />
      <div className="grid gap-3 lg:grid-cols-3">
      <div className="space-y-3 lg:col-span-2">
        {ai?.cti_summary?.threat_ip && <CtiCard ai={ai} />}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2"><ScrollText className="h-4 w-4 text-primary" />{t("triage_page.playbook")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(playbook ?? []).map((p, i) => (
              <div key={i} className="flex gap-3 rounded-md border bg-muted/30 p-2.5">
                <div className="mono w-8 shrink-0 text-center text-lg font-bold text-primary">{p.Step}</div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold">{p.Action}</span>
                    <span className="mono rounded bg-accent/40 px-1.5 text-[10px] uppercase">{p.Priority}</span>
                  </div>
                  <div className="mono text-[11px] text-muted-foreground">{p.Target}</div>
                  <p className="mt-0.5 text-xs">{p.Instructions}</p>
                  <p className="mt-0.5 text-[11px] italic text-muted-foreground">{p.Rationale}</p>
                </div>
              </div>
            ))}
            {playbook?.length === 0 && <div className="text-xs text-muted-foreground">No remediation steps required — capture is nominal.</div>}
          </CardContent>
        </Card>
        {blockIp && <BlockRules ip={blockIp} ai={ai} />}
      </div>
      <div className="space-y-3">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-sm"><Brain className="h-4 w-4 text-primary" />{t("dashboard.ai_engine")} — targets</CardTitle></CardHeader>
          <CardContent className="space-y-1.5">
            {malicious.map((s) => (
              <div key={s.ip} className="flex items-center justify-between rounded-md border bg-muted/30 px-2 py-1.5">
                <span className="mono text-xs font-semibold">{s.ip}</span>
                <span className="text-[10px] text-muted-foreground">{s.likely_type}</span>
                <Button size="sm" variant="destructive" onClick={() => setBlockIp(s.ip)}>Block</Button>
              </div>
            ))}
            {malicious.length === 0 && <div className="text-xs text-muted-foreground">No AI-flagged hostile endpoints.</div>}
          </CardContent>
        </Card>
        <Sandbox />
      </div>
      </div>
      <div className={cn("mt-3 grid gap-3", (ai?.incidents?.length ?? 0) > 0 ? "lg:grid-cols-2" : "lg:grid-cols-1")}>
        <IncidentsTable incidents={ai?.incidents ?? []} />
        <BenchmarksCard />
      </div>
    </div>
  );
}
