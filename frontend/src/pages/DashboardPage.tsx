import { useTranslation } from "react-i18next";
import { Activity, ArrowUpRight, FileSearch, HardDrive, LayoutDashboard, MessagesSquare, Radio, Timer, Wallet } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { Skeleton } from "@/components/ui/skeleton";
import { DefconGauge } from "@/components/dashboard/DefconGauge";
import { VelocityCard } from "@/components/dashboard/VelocityCard";
import { VectorMapCard } from "@/components/dashboard/VectorMapCard";
import { FourQCard } from "@/components/dashboard/FourQCard";
import { IocStrip } from "@/components/dashboard/IocStrip";
import { AiPanel } from "@/components/dashboard/AiPanel";
import { MitreHeat } from "@/components/dashboard/MitreHeat";
import { ProtocolDonut } from "@/components/dashboard/ProtocolDonut";
import { StatCard } from "@/components/dashboard/StatCard";
import { ThreatSummaryPanel } from "@/components/dashboard/ThreatSummaryPanel";
import { TopTalkers } from "@/components/dashboard/TopTalkers";
import { TrafficTimeline } from "@/components/dashboard/TrafficTimeline";
import { UploadZone } from "@/components/dashboard/UploadZone";
import { ForceGraph } from "@/components/topology/ForceGraph";
import { useJob } from "@/hooks/JobProvider";
import { useAnalysisSession, useProgress, useSummary } from "@/hooks/useAnalysis";
import { formatBytes } from "@/lib/utils";
import { Link } from "react-router-dom";

export default function DashboardPage() {
  const { t } = useTranslation();
  const { jobId } = useJob();
  const progress = useProgress(jobId);
  const { data: session } = useAnalysisSession();
  const hasData = session?.has_data || progress.status === "done";
  const { data: summary, isLoading } = useSummary(!!hasData);

  if (progress.status === "running") {
    return <UploadZone pct={progress.pct} label={progress.label} />;
  }
  if (progress.status === "error") {
    return (
      <Card className="mx-auto mt-10 max-w-md border-threat">
        <CardContent className="py-6 text-center text-sm text-threat">
          {t("common.error")}: {progress.error}
        </CardContent>
      </Card>
    );
  }
  if (!hasData)
    return (
      <div>
        <PageHeader icon={LayoutDashboard} title={t("nav.dashboard")} />
        <UploadZone pct={0} label="" />
      </div>
    );
  if (isLoading || !summary) {
    return (
      <div>
        <PageHeader icon={LayoutDashboard} title={t("nav.dashboard")} />
        <div className="grid gap-3 md:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
      </div>
    );
  }

  const hud = summary.hud as Record<string, unknown>;
  const s = summary.summary_stats;

  return (
    <div className="space-y-3">
      <PageHeader icon={LayoutDashboard} title={t("nav.dashboard")} hint={summary.filename} />

      {/* KPI hero row */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-9">
        <StatCard label={t("dashboard.packets")} value={s.Total_Packets.toLocaleString()} icon={Wallet} delay={0} />
        <StatCard label={t("dashboard.volume")} value={s.Total_Bytes_Formatted} icon={HardDrive} delay={0.04} />
        <StatCard label={t("dashboard.duration")} value={`${s.Duration_Seconds.toFixed(2)}s`} icon={Timer} delay={0.08} />
        <StatCard label={t("dashboard.transfer")} value={s.Packet_Rate} sub={s.Data_Rate_Kbps} icon={Activity} delay={0.12} />
        <StatCard label={t("dashboard.conversations")} value={summary.streams.length} icon={MessagesSquare} delay={0.16} />
        <StatCard label={t("dashboard.unique_ips")} value={summary.ip_profiles.length} icon={Radio} delay={0.2} />
        <StatCard label={t("carved_page.title")} value={`${hud.carved_count ?? summary.carved.length}`}
          sub={formatBytes((hud.carved_bytes as number) ?? 0)} icon={FileSearch} delay={0.24} />
        <DefconGauge defcon={summary.defcon} titleClassName="text-[11px]" className="col-span-2 md:col-span-2 xl:col-span-2" />
      </div>

      <TrafficTimeline />

      <div className="grid gap-3 lg:grid-cols-3">
        <ProtocolDonut dist={summary.protocol_dist} />
        <TopTalkers links={summary.topology.links} />
        <ThreatSummaryPanel threats={summary.threats} defcon={summary.defcon} />
      </div>

      <AiPanel ai={summary.ai_data} />

      <div className="grid gap-3 lg:grid-cols-2">
        <VelocityCard ai={summary.ai_data} />
        <VectorMapCard ai={summary.ai_data} />
      </div>

      <MitreHeat threats={summary.threats} ai={summary.ai_data} />

      <div className="grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-1">
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-4 w-4" />{t("dashboard.topology")}
            </CardTitle>
            <Link to="/topology" className="flex items-center gap-0.5 text-[11px] text-primary hover:underline">
              {t("topology_page.expand")} <ArrowUpRight className="h-3 w-3" />
            </Link>
          </CardHeader>
          <CardContent className="p-2">
            <ForceGraph nodes={summary.topology.nodes} links={summary.topology.links} height={240} mini
              onNodeClick={() => undefined} />
          </CardContent>
        </Card>
        <FourQCard ai={summary.ai_data} />
      </div>

      <IocStrip summary={summary} />
    </div>
  );
}
