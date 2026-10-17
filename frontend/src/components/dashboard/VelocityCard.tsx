import { useTranslation } from "react-i18next";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Gauge } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { AiData } from "@/services/types";

export function VelocityCard({ ai }: { ai?: AiData }) {
  const { t } = useTranslation();
  const rows = ai?.velocity_timeline ?? [];
  return (
    <Card className="h-full">
      <CardHeader className="pb-1">
        <CardTitle className="flex items-center gap-2">
          <Gauge className="h-4 w-4 text-primary" />{t("dashboard.velocity")}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-2 pr-4">
        {rows.length === 0 ? (
          <div className="py-8 text-center text-xs text-muted-foreground">{t("dashboard.no_incident_velocity")}</div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={rows} margin={{ top: 8, right: 8, left: -22, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
              <XAxis dataKey="time" tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" interval="preserveStartEnd" minTickGap={40} />
              <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
              />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="attack" stackId="f" name="Attack" fill={SEVERITY_COLORS.CRITICAL} isAnimationActive={false} />
              <Bar dataKey="suspicious" stackId="f" name="Suspicious" fill={SEVERITY_COLORS.HIGH} isAnimationActive={false} />
              <Bar dataKey="normal" stackId="f" name="Normal" fill={SEVERITY_COLORS.LOW} opacity={0.45} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </CardContent>
    </Card>
  );
}
