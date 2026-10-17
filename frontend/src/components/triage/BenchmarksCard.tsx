import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { BarChart3, ChevronDown, GraduationCap } from "lucide-react";
import { api } from "@/services/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-muted/30 px-2 py-1.5 text-center">
      <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mono text-sm font-bold text-primary">{value}</div>
    </div>
  );
}

export function BenchmarksCard() {
  const { t } = useTranslation();
  const { data } = useQuery({ queryKey: ["ai-benchmarks"], queryFn: api.aiBenchmarks });
  const bm = data?.benchmark;
  const cm = bm?.confusion_matrix;
  const viva = data?.viva_guide ?? [];
  const [open, setOpen] = useState<number | null>(null);

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-primary" />{t("triage_page.benchmarks")}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {bm && (
            <>
              <div className="grid grid-cols-3 gap-1.5 sm:grid-cols-5">
                <Kpi label={t("triage_page.bm_accuracy")} value={`${bm.accuracy.toFixed(2)}%`} />
                <Kpi label={t("triage_page.bm_precision")} value={`${bm.precision.toFixed(2)}%`} />
                <Kpi label={t("triage_page.bm_recall")} value={`${bm.recall.toFixed(2)}%`} />
                <Kpi label={t("triage_page.bm_f1")} value={`${bm.f1_score.toFixed(2)}%`} />
                <Kpi label={t("triage_page.bm_samples")} value={bm.test_samples.toLocaleString()} />
              </div>
              {cm && (
                <div className="grid grid-cols-2 overflow-hidden rounded-md border text-center text-[11px]">
                  <div className="border-e border-b bg-success/10 p-2"><div className="mono font-bold text-success">{cm.tn.toLocaleString()}</div>True Neg</div>
                  <div className="border-b bg-warn/10 p-2"><div className="mono font-bold text-warn">{cm.fp.toLocaleString()}</div>False Pos</div>
                  <div className="border-e border-t bg-warn/10 p-2"><div className="mono font-bold text-warn">{cm.fn.toLocaleString()}</div>False Neg</div>
                  <div className="border-t bg-success/10 p-2"><div className="mono font-bold text-success">{cm.tp.toLocaleString()}</div>True Pos</div>
                </div>
              )}
              {bm.class_reports.length > 0 && (
                <div className="max-h-44 overflow-y-auto rounded-md border">
                  <table className="mono w-full text-[10px]">
                    <thead className="sticky top-0 bg-muted/80 text-muted-foreground backdrop-blur">
                      <tr>
                        <th className="p-1.5 text-start">{t("triage_page.bm_class")}</th>
                        <th className="p-1.5 text-end">Precision</th>
                        <th className="p-1.5 text-end">Recall</th>
                        <th className="p-1.5 text-end">F1</th>
                        <th className="p-1.5 text-end">Support</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bm.class_reports.map((c, i) => (
                        <tr key={i} className="border-t">
                          <td className="p-1.5">{c.class}</td>
                          <td className="p-1.5 text-end">{c.precision.toFixed(2)}</td>
                          <td className="p-1.5 text-end">{c.recall.toFixed(2)}</td>
                          <td className="p-1.5 text-end font-bold">{c.f1.toFixed(2)}</td>
                          <td className="p-1.5 text-end text-muted-foreground">{c.support.toLocaleString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
          {!bm && <div className="py-4 text-center text-xs text-muted-foreground">…</div>}
        </CardContent>
      </Card>

      {viva.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2">
              <GraduationCap className="h-4 w-4 text-primary" />{t("triage_page.viva")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {viva.map((v, i) => (
              <div key={i} className="rounded-md border bg-muted/30">
                <button
                  className="flex w-full items-center justify-between gap-2 p-2 text-start text-[12px] font-medium hover:bg-accent/30"
                  onClick={() => setOpen(open === i ? null : i)}
                >
                  <span>{v.question}</span>
                  <ChevronDown className={cn("h-4 w-4 shrink-0 text-muted-foreground transition-transform", open === i && "rotate-180")} />
                </button>
                {open === i && (
                  <div className="border-t p-2 text-[11px] leading-relaxed text-muted-foreground">{v.answer}</div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
