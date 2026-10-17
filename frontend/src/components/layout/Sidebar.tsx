import React from "react";
import { useTranslation } from "react-i18next";
import { NavLink } from "react-router-dom";
import {
  Activity,
  Cpu,
  FileSearch,
  FileText,
  Globe2,
  LayoutDashboard,
  Network,
  ScanLine,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAnalysisSession } from "@/hooks/useAnalysis";

const NAV = [
  { to: "/", key: "nav.dashboard", icon: LayoutDashboard, end: true },
  { to: "/dissector", key: "nav.dissector", icon: ScanLine },
  { to: "/threats", key: "nav.threats", icon: ShieldAlert },
  { to: "/topology", key: "nav.topology", icon: Network },
  { to: "/streams", key: "nav.streams", icon: Activity },
  { to: "/carved", key: "nav.carved", icon: FileSearch },
  { to: "/encyclopedia", key: "nav.encyclopedia", icon: Globe2 },
  { to: "/triage", key: "nav.triage", icon: Cpu },
  { to: "/reports", key: "nav.reports", icon: FileText },
];

export function Sidebar({ className }: { className?: string }) {
  const { t } = useTranslation();
  const { data: session } = useAnalysisSession();
  const hasData = session?.has_data;

  return (
    <aside className={cn("flex w-60 flex-col border-e bg-card/60", className)}>
      <div className="flex items-center gap-3 p-4">
        <img src="/emblem.jpg" alt="logo" className="h-12 w-12 rounded-md object-cover ring-1 ring-border" />
        <div>
          <div className="font-display text-sm font-bold leading-tight">{t("app.name")}</div>
          <div className="text-[11px] leading-tight text-muted-foreground">{t("app.tagline")}</div>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 pb-4">
        {NAV.map(({ to, key, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent/50 hover:text-foreground",
                isActive && "bg-accent text-accent-foreground dark:shadow-neon",
                !hasData && to !== "/" && "pointer-events-none opacity-40",
              )
            }
          >
            <Icon className="h-4 w-4" />
            {t(key)}
          </NavLink>
        ))}
      </nav>
      <div className="border-t p-3 text-[11px] text-muted-foreground">
        {hasData ? (
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-success animate-pulse-glow" />
            {session?.filename}
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-muted-foreground/40" />
            {t("common.no_data")}
          </span>
        )}
      </div>
    </aside>
  );
}
