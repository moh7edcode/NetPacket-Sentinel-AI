import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ArrowRight, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { Defcon, Threat } from "@/services/types";

export function ThreatSummaryPanel({ threats, defcon }: { threats: Threat[]; defcon: Defcon }) {
  const { t } = useTranslation();
  const counts = {
    CRITICAL: defcon.critical,
    HIGH: defcon.high,
    MEDIUM: defcon.medium,
    LOW: defcon.low,
  };

  return (
    <Card className="h-full">
      <CardHeader className="flex-row items-center justify-between pb-1">
        <CardTitle className="flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-threat" />
          {t("dashboard.threats")}
        </CardTitle>
        <Link to="/threats" className="flex items-center gap-1 text-[11px] text-primary hover:underline">
          {t("nav.threats")} <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent className="p-3">
        <div className="grid grid-cols-4 gap-2">
          {(Object.keys(counts) as (keyof typeof counts)[]).map((sev) => (
            <div key={sev} className="rounded-md border p-2 text-center">
              <div className="mono text-xl font-bold" style={{ color: SEVERITY_COLORS[sev] }}>
                {counts[sev]}
              </div>
              <div className="text-[10px] uppercase text-muted-foreground">{sev}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 space-y-1.5">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground">
            {t("dashboard.latest_alerts")}
          </div>
          {threats.length === 0 && (
            <div className="text-[12px] text-muted-foreground">No threat rules triggered — DEFCON 5 posture.</div>
          )}
          {threats.slice(0, 5).map((th) => (
            <Link
              key={th.id}
              to={`/threats?alert=${th.id}`}
              className="block rounded-md border border-transparent bg-muted/40 px-2.5 py-1.5 transition-colors hover:border-primary/40"
            >
              <div className="flex items-center justify-between gap-2">
                <SeverityBadge severity={th.severity} />
                <span className="mono text-[10px] text-muted-foreground">{th.mitre_id}</span>
              </div>
              <div className="mt-1 truncate text-xs font-medium">{th.title}</div>
              <div className="mono truncate text-[10px] text-muted-foreground">
                {th.src} → {th.dst} · {th.packet_count} {t("common.packets")}
              </div>
            </Link>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
