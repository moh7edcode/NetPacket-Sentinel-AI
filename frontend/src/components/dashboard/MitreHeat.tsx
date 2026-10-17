import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { LayoutGrid } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AiData, Threat } from "@/services/types";

export function MitreHeat({ threats, ai }: { threats: Threat[]; ai?: AiData }) {
  const { t } = useTranslation();
  const hits = new Set<string>();
  threats.forEach((th) => th.mitre_id && hits.add(th.mitre_id.split(".")[0]));
  (ai?.active_mitre_tids ?? []).forEach((id) => hits.add(id.split(".")[0]));
  const tactics = ai?.matrix_tactics ?? [];

  return (
    <Card className="h-full">
      <CardHeader className="flex-row items-center justify-between pb-1">
        <CardTitle className="flex items-center gap-2"><LayoutGrid className="h-4 w-4 text-primary" />{t("dashboard.mitre")}</CardTitle>
        <Link to="/threats" className="text-[11px] text-primary hover:underline">
          {t("threats.matrix")}
        </Link>
      </CardHeader>
      <CardContent className="grid grid-flow-col auto-cols-[minmax(88px,1fr)] gap-2 overflow-x-auto p-3 pt-1">
        {tactics.map((tac) => {
          const hit = tac.techniques.filter((tk) => hits.has(tk.id.split(".")[0]));
          const intensity = hit.length ? Math.min(1, hit.length / tac.techniques.length) : 0;
          return (
            <div key={tac.sub} className="rounded-md border p-2">
              <div className="mb-1 flex items-baseline justify-between">
                <span className="text-[10px] font-semibold uppercase leading-tight">{tac.name}</span>
                <span className="mono text-[9px] text-muted-foreground">{tac.sub}</span>
              </div>
              <div className="space-y-1">
                {tac.techniques.map((tk, i) => {
                  const on = hits.has(tk.id.split(".")[0]);
                  return (
                    <div
                      key={i}
                      title={`${tk.id} ${tk.name}${on ? " — DETECTED" : ""}`}
                      className={`truncate rounded px-1.5 py-1 text-[9px] ${on ? "dark:animate-pulse-glow" : "text-muted-foreground/70"}`}
                      style={
                        on
                          ? {
                              backgroundColor: `rgba(239,68,68,${0.18 + intensity * 0.5})`,
                              color: "#ef4444",
                              boxShadow: "0 0 10px rgba(239,68,68,0.35)",
                            }
                          : { backgroundColor: "hsl(var(--muted))" }
                      }
                    >
                      {tk.id} {tk.name.slice(0, 18)}
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
