import { useTranslation } from "react-i18next";
import { Globe2, ShieldX } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { Summary } from "@/services/types";

function verdictColor(v: string): string {
  if (!v) return "#64748b";
  const s = v.toUpperCase();
  if (s.includes("MALIC") || s.includes("SUSPIC")) return "#ef4444";
  if (s.includes("CLEAN")) return "#10b981";
  return "#64748b";
}

export function IocStrip({ summary }: { summary: Summary }) {
  const { t } = useTranslation();
  const geoByIp = new Map(summary.geo.map((g) => [g.IP, g]));
  const ips = summary.intel?.public_ips ?? [];
  const domains = summary.intel?.domains ?? [];

  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="flex items-center gap-2">
          <ShieldX className="h-4 w-4 text-threat" />
          {t("dashboard.iocs")}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-2 p-3 pt-1">
        {ips.length === 0 && domains.length === 0 && (
          <div className="text-[12px] text-muted-foreground">No external IoCs extracted from this capture.</div>
        )}
        {ips.map((e) => {
          const g = geoByIp.get(e.Target);
          return (
            <div key={e.Target} className="flex items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5">
              <span className="mono text-xs font-semibold">{e.Target}</span>
              <span
                className="rounded-full px-2 py-0.5 text-[10px] font-bold"
                style={{ color: verdictColor(e.Verdict), border: `1px solid ${verdictColor(e.Verdict)}` }}
              >
                {e.Verdict} {e.Reputation_Score != null ? `· ${e.Reputation_Score}` : ""}
              </span>
              {g && !g.Is_Private && (
                <span className="text-[10px] text-muted-foreground">
                  {g.Country} · {g.ASN}
                </span>
              )}
            </div>
          );
        })}
        {domains.map((d) => (
          <div key={d.Target} className="flex items-center gap-2 rounded-md border bg-muted/40 px-2.5 py-1.5">
            <Globe2 className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="mono text-xs">{d.Target}</span>
            <span
              className="rounded-full px-2 py-0.5 text-[10px] font-bold"
              style={{ color: verdictColor(d.Verdict), border: `1px solid ${verdictColor(d.Verdict)}` }}
            >
              {d.Verdict}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
