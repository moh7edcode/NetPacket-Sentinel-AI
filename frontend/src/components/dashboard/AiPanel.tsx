import { useTranslation } from "react-i18next";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Brain } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { AiData } from "@/services/types";

export function AiPanel({ ai }: { ai?: AiData }) {
  const { t } = useTranslation();

  if (!ai?.has_data) {
    return (
      <Card>
        <CardHeader className="pb-1">
          <CardTitle className="flex items-center gap-2"><Brain className="h-4 w-4 text-primary" />{t("dashboard.ai_engine")}</CardTitle>
        </CardHeader>
        <CardContent className="py-6 text-center text-[12px] text-muted-foreground">
          {ai?.error ?? t("common.no_data")}
        </CardContent>
      </Card>
    );
  }

  const total = ai.total_flows || 1;
  const rf = [
    { name: "Attack", count: ai.attack_count, fill: "#ef4444" },
    { name: "Suspicious", count: ai.suspicious_count, fill: "#f59e0b" },
    { name: "Normal", count: ai.normal_count, fill: "#10b981" },
  ];
  const zeroDay = ai.anomaly_hist.length
    ? ai.anomaly_hist.slice(Math.floor(ai.anomaly_hist.length * 0.8)).reduce((s, b) => s + b.count, 0)
    : 0;

  return (
    <Card className="h-full">
      <CardHeader className="flex-row items-center justify-between pb-1">
        <CardTitle className="flex items-center gap-2">
          <Brain className="h-4 w-4 text-primary" />
          {t("dashboard.ai_engine")}
        </CardTitle>
        <span className="mono text-[11px] text-muted-foreground">{ai.total_flows} flows</span>
      </CardHeader>
      <CardContent className="grid gap-3 p-3 pt-1 md:grid-cols-2">
        <div>
          <div className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">{t("dashboard.rf")}</div>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={rf} layout="vertical" margin={{ left: 8, right: 24 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={74} tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
              <Tooltip
                contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                formatter={(v: number, n) => [`${v} (${((v / total) * 100).toFixed(1)}%)`, n]}
              />
              <Bar dataKey="count" radius={4}>
                {rf.map((r, i) => <Cell key={i} fill={r.fill} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div>
          <div className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">{t("dashboard.iforest")}</div>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={ai.anomaly_hist} margin={{ left: -22, right: 4 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
              <XAxis dataKey="bin" tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" />
              <YAxis tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" />
              <Tooltip
                contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                labelFormatter={(v) => `score ${Number(v).toFixed(3)}`}
              />
              <Bar dataKey="count" fill="#6366f1" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="col-span-full flex items-center justify-between rounded-md border bg-muted/40 px-3 py-2">
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{t("dashboard.zeroday")}</div>
          <div className="mono text-sm font-bold text-threat">{zeroDay}</div>
          <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{t("dashboard.confidence")}</div>
          <div className="mono text-sm font-bold text-primary dark:animate-pulse-glow">{ai.attack_pct}% attack</div>
        </div>
      </CardContent>
    </Card>
  );
}
