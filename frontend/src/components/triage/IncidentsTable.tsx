import { useTranslation } from "react-i18next";
import { Link2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/SeverityBadge";
import type { IncidentRow } from "@/services/types";

export function IncidentsTable({ incidents }: { incidents: IncidentRow[] }) {
  const { t } = useTranslation();
  if (!incidents.length) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <Link2 className="h-4 w-4 text-primary" />{t("triage_page.incidents")}
          <span className="ms-1 text-[11px] font-normal text-muted-foreground">({incidents.length})</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="max-h-64 overflow-y-auto">
        <table className="mono w-full text-[11px]">
          <thead className="sticky top-0 bg-muted/80 text-muted-foreground backdrop-blur">
            <tr>
              <th className="p-1.5 text-start">{t("triage_page.source")}</th>
              <th className="p-1.5 text-start">{t("triage_page.targets")}</th>
              <th className="p-1.5 text-end">Flows</th>
              <th className="p-1.5 text-end">Attack</th>
              <th className="p-1.5 text-start">{t("triage_page.confidence")}</th>
              <th className="p-1.5 text-start">MITRE</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc) => (
              <tr key={inc.incident_id} className="border-t align-top">
                <td className="p-1.5 font-semibold">{inc.source_ip}</td>
                <td className="max-w-[180px] p-1.5 text-muted-foreground">{inc.targets.slice(0, 4).join(", ")}{inc.targets.length > 4 ? "…" : ""}</td>
                <td className="p-1.5 text-end">{inc.flows_count}</td>
                <td className="p-1.5 text-end font-bold text-threat">{inc.attack_flows_count}</td>
                <td className="p-1.5">
                  <div className="flex items-center gap-1.5">
                    <div className="h-1.5 w-14 overflow-hidden rounded-full bg-muted">
                      <div className="h-full rounded-full bg-primary" style={{ width: `${inc.confidence}%` }} />
                    </div>
                    <span className="text-[10px]">{inc.confidence}%</span>
                    <SeverityBadge severity={inc.severity.toUpperCase()} />
                  </div>
                  <div className="mt-0.5 text-[10px] italic text-muted-foreground">{inc.indicators.slice(0, 2).join(" · ")}</div>
                </td>
                <td className="p-1.5 text-primary">{inc.mitre_techniques.slice(0, 3).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
