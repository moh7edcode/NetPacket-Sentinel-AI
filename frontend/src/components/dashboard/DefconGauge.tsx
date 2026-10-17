import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn, SEVERITY_COLORS } from "@/lib/utils";
import type { Defcon } from "@/services/types";

export function DefconGauge({
  defcon,
  className,
  titleClassName,
}: {
  defcon: Defcon;
  className?: string;
  titleClassName?: string;
}) {
  const { t } = useTranslation();
  const pct = ((5 - defcon.level) / 5) * 100 + 10;
  return (
    <Card className={cn("h-full", className)}>
      <CardHeader className="pb-1">
        <CardTitle className={titleClassName}>{t("dashboard.defcon")}</CardTitle>
      </CardHeader>
      <CardContent className="flex items-center gap-4 p-4 pt-1">
        <div className="relative h-20 w-20 shrink-0">
          <svg viewBox="0 0 80 80" className="h-full w-full -rotate-[135deg]">
            <circle cx="40" cy="40" r="32" fill="none" stroke="hsl(var(--muted))" strokeWidth="7"
              strokeDasharray={`${0.75 * 201} 201`} strokeLinecap="round" />
            <circle cx="40" cy="40" r="32" fill="none" stroke={defcon.posture_color} strokeWidth="7"
              strokeDasharray={`${(pct / 100) * 0.75 * 201} 201`} strokeLinecap="round"
              className={defcon.level <= 2 ? "animate-pulse-glow" : ""} />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="mono text-2xl font-bold" style={{ color: defcon.posture_color }}>
              {defcon.level}
            </span>
            <span className="text-[9px] uppercase text-muted-foreground">DEFCON</span>
          </div>
        </div>
        <div className="min-w-0">
          <div className="text-sm font-bold" style={{ color: defcon.posture_color }}>{defcon.posture}</div>
          <div className="mono mt-0.5 text-[11px] text-muted-foreground">{defcon.title}</div>
          <div className="mono mt-1 flex gap-2 text-[11px]">
            <span style={{ color: SEVERITY_COLORS.CRITICAL }}>C {defcon.critical}</span>
            <span style={{ color: SEVERITY_COLORS.HIGH }}>H {defcon.high}</span>
            <span style={{ color: SEVERITY_COLORS.MEDIUM }}>M {defcon.medium}</span>
            <span style={{ color: SEVERITY_COLORS.LOW }}>L {defcon.low}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
