import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Globe2, ShieldCheck, ShieldX } from "lucide-react";
import { api } from "@/services/api";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/SeverityBadge";
import { useAnalysisSession } from "@/hooks/useAnalysis";

export default function EncyclopediaPage() {
  const { t, i18n } = useTranslation();
  const { data: catalog } = useQuery({ queryKey: ["catalog"], queryFn: api.catalog });
  const { data: session } = useAnalysisSession();
  const [q, setQ] = useState("");

  const items = useMemo(
    () =>
      (catalog ?? []).filter((c) => {
        const name = i18n.language === "ar" ? c.name_ar : c.name_en;
        return `${name} ${c.category} ${c.mitre_id}`.toLowerCase().includes(q.toLowerCase());
      }),
    [catalog, q, i18n.language],
  );

  return (
    <div className="space-y-3">
      <PageHeader
        icon={Globe2}
        title={t("nav.encyclopedia")}
        count={items.length}
        actions={
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t("encyclopedia_page.search")}
            className="w-64 text-xs" disabled={!session?.has_data} />
        }
      />
      {!session?.has_data && (
        <div className="text-sm text-muted-foreground">{t("common.no_data")}</div>
      )}
      <div className="grid gap-3 md:grid-cols-2">
        {items.map((a) => (
          <Card key={a.attack_id} className={a.detected ? "border-threat/60" : ""}>
            <CardContent className="space-y-2 p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-sm font-bold">{i18n.language === "ar" ? a.name_ar : a.name_en}</div>
                  <div className="mono text-[10px] uppercase text-muted-foreground">{a.category} · {a.mitre_id} · {a.mitre_tactic}</div>
                </div>
                {a.detected ? (
                  <span className="flex items-center gap-1 rounded-full bg-threat/15 px-2 py-0.5 text-[10px] font-bold text-threat">
                    <ShieldX className="h-3 w-3" /> {t("threats.detected")}
                  </span>
                ) : (
                  <span className="flex items-center gap-1 rounded-full bg-success/10 px-2 py-0.5 text-[10px] font-bold text-success">
                    <ShieldCheck className="h-3 w-3" /> {t("threats.not_detected")}
                  </span>
                )}
                <SeverityBadge severity={a.severity} />
              </div>
              <p className="text-xs leading-snug text-muted-foreground">
                <span className="font-semibold text-foreground">{t("encyclopedia_page.mechanism")}: </span>
                {a.mechanism}
              </p>
              <p className="text-xs leading-snug">
                <span className="font-semibold">{t("encyclopedia_page.mitigation")}: </span>{a.mitigation}
              </p>
              <div className="flex flex-wrap gap-1">
                {(typeof a.rules === "string" ? a.rules.split(/\n+/) : a.rules ?? [])
                  .map((r) => r.trim())
                  .filter(Boolean)
                  .map((r, i) => (
                    <span key={i} className="mono rounded bg-muted px-1.5 py-0.5 text-[9px] text-muted-foreground">{r}</span>
                  ))}
              </div>
              {a.detected && (
                <div className="mono border-t pt-1.5 text-[10px] text-threat">
                  {t("encyclopedia_page.triggered_packets")}: {a.matched_packets.slice(0, 12).join(", ")}
                  {a.matched_packets.length > 12 ? ` … (+${a.matched_packets.length - 12})` : ""}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
