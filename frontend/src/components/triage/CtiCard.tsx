import { useTranslation } from "react-i18next";
import { ClipboardCopy, ScanEye, ShieldAlert } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { AiData } from "@/services/types";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="truncate text-[12px]">{children}</div>
    </div>
  );
}

export function CtiCard({ ai }: { ai?: AiData }) {
  const { t } = useTranslation();
  const c = ai?.cti_summary;
  if (!c?.threat_ip) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-primary" />{t("triage_page.cti")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-[12px]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="mono rounded-md border px-2 py-0.5 font-bold" style={{ color: SEVERITY_COLORS.CRITICAL, borderColor: SEVERITY_COLORS.CRITICAL }}>
            {c.threat_ip}
          </span>
          <span className="mono rounded bg-threat/10 px-2 py-0.5 text-[11px] font-bold text-threat">VT {c.vt_score}/100</span>
          <span className="mono rounded px-2 py-0.5 text-[11px] font-bold"
            style={{ background: `${SEVERITY_COLORS[c.severity] ?? SEVERITY_COLORS.CRITICAL}1f`, color: SEVERITY_COLORS[c.severity] ?? SEVERITY_COLORS.CRITICAL }}>
            {c.severity}
          </span>
          <span className="ms-auto mono text-[11px] text-muted-foreground">{c.mitre_tid} · {c.tactic}</span>
        </div>
        <div className="grid grid-cols-2 gap-2 rounded-md border bg-muted/30 p-2">
          <Field label={t("triage_page.technique")}>{c.technique} / {c.subtechnique}</Field>
          <Field label={t("triage_page.targets")}>{(c.targets ?? []).join(", ")}</Field>
          <Field label={t("triage_page.window")}>{c.time_window}</Field>
          <Field label={t("triage_page.peak_rate")}>{c.peak_rate}</Field>
          <div className="col-span-2"><Field label={t("triage_page.mitigation")}>{c.mitigation}</Field></div>
        </div>
        {c.soc_action && <div className="text-[11px] italic text-muted-foreground">{c.soc_action}</div>}
        {c.firewall_cmd && (
          <div className="flex items-start gap-2 rounded-md border border-threat/40 bg-threat/10 p-2">
            <code className="mono min-w-0 flex-1 break-all text-[10px] text-threat">{c.firewall_cmd}</code>
            <Button size="sm" variant="ghost" className="shrink-0"
              onClick={() => { navigator.clipboard.writeText(c.firewall_cmd); toast.success(t("triage_page.copied")); }}>
              <ClipboardCopy className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}
        {ai?.evidence_hashes?.sha256 && (
          <div className="flex items-center gap-1.5 border-t pt-2 text-[10px] text-muted-foreground">
            <ScanEye className="h-3.5 w-3.5" />
            <span className="uppercase">{t("triage_page.evidence")}</span>
            <code className="mono truncate" title={ai.evidence_hashes.sha256}>SHA-256 {ai.evidence_hashes.sha256.slice(0, 24)}…</code>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
