import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useTranslation } from "react-i18next";
import { Activity } from "lucide-react";
import { api } from "@/services/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { TimelineSeries } from "@/services/types";

export function TrafficTimeline({ markers }: { markers?: TimelineSeries["markers"] }) {
  const { t } = useTranslation();
  const { data } = useQuery({ queryKey: ["timeline-series"], queryFn: api.timelineSeries });

  const series = data?.series ?? [];
  const alertMarks = markers ?? data?.markers ?? [];
  const byTime = useMemo(() => {
    const m = new Map<number, TimelineSeries["markers"][number][]>();
    alertMarks.forEach((a) => {
      const k = Math.floor(a.time);
      m.set(k, [...(m.get(k) ?? []), a]);
    });
    return m;
  }, [alertMarks]);

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between pb-1">
        <CardTitle className="flex items-center gap-2"><Activity className="h-4 w-4 text-primary" />{t("dashboard.timeline")}</CardTitle>
        <span className="text-[11px] text-muted-foreground">
          {alertMarks.length} {t("dashboard.latest_alerts").toLowerCase()}
        </span>
      </CardHeader>
      <CardContent className="p-2 pr-4">
        <ResponsiveContainer width="100%" height={220}>
          <ComposedChart data={series} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
            <defs>
              <linearGradient id="pktFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.5} />
                <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis dataKey="t" tick={{ fontSize: 10 }} tickFormatter={(v) => `${v}s`} stroke="hsl(var(--muted-foreground))" />
            <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
            <Tooltip
              contentStyle={{
                background: "hsl(var(--popover))",
                border: "1px solid hsl(var(--border))",
                borderRadius: 8,
                fontSize: 12,
              }}
              formatter={(value: number, name: string) => [value.toLocaleString(), name === "packets" ? "Packets/s" : "Bytes/s"]}
              labelFormatter={(v) => `t = ${v}s`}
            />
            <Area type="monotone" dataKey="packets" stroke="#22d3ee" fill="url(#pktFill)" strokeWidth={1.5} isAnimationActive={false} />
            {series.map((b) =>
              (byTime.get(Math.floor(b.t)) ?? []).map((m) => (
                <ReferenceLine
                  key={`${m.rule_id}-${m.time}`}
                  x={b.t}
                  stroke={SEVERITY_COLORS[m.severity] ?? "#ef4444"}
                  strokeDasharray="4 3"
                  strokeWidth={1.5}
                  label={{ value: "⚠", fill: SEVERITY_COLORS[m.severity] ?? "#ef4444", fontSize: 11, position: "top" }}
                />
              )),
            )}
          </ComposedChart>
        </ResponsiveContainer>
        {alertMarks.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1.5 px-2">
            {alertMarks.slice(0, 6).map((m, i) => (
              <span
                key={i}
                className="mono rounded border px-1.5 py-0.5 text-[10px]"
                style={{ borderColor: SEVERITY_COLORS[m.severity], color: SEVERITY_COLORS[m.severity] }}
                title={`${m.title} — ${m.src} → ${m.dst} @ t+${m.time}s (${m.packet_count} packets)`}
              >
                t+{m.time}s {m.mitre_id} {m.title.slice(0, 28)}
              </span>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
