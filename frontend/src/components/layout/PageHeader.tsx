import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface PageHeaderProps {
  icon: LucideIcon;
  title: string;
  count?: number;
  hint?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

export function PageHeader({ icon: Icon, title, count, hint, actions, className }: PageHeaderProps) {
  return (
    <div className={cn("mb-3 flex flex-wrap items-center justify-between gap-2 border-b pb-2", className)}>
      <div className="flex items-center gap-2">
        <Icon className="h-5 w-5 text-primary" />
        <h2 className="font-display text-lg font-bold leading-none">
          {title}
          {count !== undefined && <span className="ms-1.5 text-muted-foreground">({count})</span>}
        </h2>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        {hint && <span className="mono text-[11px] text-muted-foreground">{hint}</span>}
        {actions}
      </div>
    </div>
  );
}
