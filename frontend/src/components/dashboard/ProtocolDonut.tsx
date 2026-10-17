import { useTranslation } from "react-i18next";
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { PieChart as PieChartIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ProtocolDist } from "@/services/types";

const PALETTE = [
  "#22d3ee", "#6366f1", "#10b981", "#f59e0b", "#ef4444",
  "#8b5cf6", "#06b6d4", "#84cc16", "#f97316", "#64748b",
];

export function ProtocolDonut({ dist }: { dist: ProtocolDist[] }) {
  const { t } = useTranslation();
  const top = dist.slice(0, 9);
  const other = dist.slice(9);
  const data = [
    ...top.map((d) => ({ name: d.Protocol, value: d.Count })),
    ...(other.length ? [{ name: "Other", value: other.reduce((s, d) => s + d.Count, 0) }] : []),
  ];

  return (
    <Card>
      <CardHeader className="pb-1">
        <CardTitle className="flex items-center gap-2"><PieChartIcon className="h-4 w-4 text-primary" />{t("dashboard.protocols")}</CardTitle>
      </CardHeader>
      <CardContent className="p-2">
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius={55} outerRadius={82}
              paddingAngle={2} strokeWidth={0}>
              {data.map((_, i) => (
                <Cell key={i} fill={PALETTE[i % PALETTE.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: "hsl(var(--popover))",
                border: "1px solid hsl(var(--border))",
                borderRadius: 8,
                fontSize: 12,
              }}
              formatter={(v: number, n) => {
                const pct = ((v / data.reduce((s, d) => s + d.value, 0)) * 100).toFixed(1);
                return [`${v.toLocaleString()} (${pct}%)`, n];
              }}
            />
            <Legend wrapperStyle={{ fontSize: 11 }} />
          </PieChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
