import { Badge } from "@/components/ui/badge";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { Severity } from "@/services/types";

const BG: Record<Severity, string> = {
  CRITICAL: "rgba(239,68,68,0.14)",
  HIGH: "rgba(249,115,22,0.14)",
  MEDIUM: "rgba(234,179,8,0.16)",
  LOW: "rgba(59,130,246,0.14)",
  INFO: "rgba(100,116,139,0.14)",
};

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const s = (severity || "INFO").toUpperCase() as Severity;
  return (
    <Badge
      variant="outline"
      className="border-0 font-mono"
      style={{ backgroundColor: BG[s] ?? BG.INFO, color: SEVERITY_COLORS[s] ?? SEVERITY_COLORS.INFO }}
    >
      {s}
    </Badge>
  );
}
