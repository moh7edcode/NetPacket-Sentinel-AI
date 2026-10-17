import { motion } from "framer-motion";
import { Card, CardContent } from "@/components/ui/card";
import type { LucideIcon } from "lucide-react";

export function StatCard({
  label,
  value,
  sub,
  icon: Icon,
  accent = "text-primary",
  delay = 0,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: LucideIcon;
  accent?: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
    >
      <Card className="h-full">
        <CardContent className="flex items-start gap-3 p-4">
          <div className={`rounded-md bg-accent/40 p-2 ${accent}`}>
            <Icon className="h-4 w-4" />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
            <div className="mono truncate text-base font-bold leading-tight" title={String(value)}>{value}</div>
            {sub && <div className="text-[11px] text-muted-foreground">{sub}</div>}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
