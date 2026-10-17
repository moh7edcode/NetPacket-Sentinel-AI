import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Download, FileText } from "lucide-react";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { DefconGauge } from "@/components/dashboard/DefconGauge";
import { SeverityBadge } from "@/components/SeverityBadge";

const FORMATS = ["html", "json", "csv", "dashboard"] as const;

export default function ReportsPage() {
  const { t } = useTranslation();
  const { data: summary } = useQuery({ queryKey: ["summary"], queryFn: api.summary, enabled: true });
  const [urls, setUrls] = useState<Record<string, string>>({});
  const gen = useMutation({
    mutationFn: (fmt: (typeof FORMATS)[number]) => api.reportGenerate(fmt),
    onSuccess: (d) => {
      setUrls((u) => ({ ...u, [d.format]: d.download_url }));
      toast.success(`${t("reports_page.generated")}: ${d.filename}`);
    },
    onError: (e) => toast.error(String(e)),
  });

  return (
    <div className="space-y-3">
      <PageHeader icon={FileText} title={t("nav.reports")} />
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {FORMATS.map((f) => (
          <Card key={f}>
            <CardContent className="flex flex-col gap-2 p-4">
              <div className="flex items-center gap-2 text-sm font-semibold">
                <FileText className="h-4 w-4 text-primary" />
                {t(`reports_page.${f}`)}
              </div>
              <Button size="sm" onClick={() => gen.mutate(f)} disabled={gen.isPending || !summary?.has_data}>
                {gen.isPending && gen.variables === f ? t("reports_page.generating") : t("reports_page.generate")}
              </Button>
              {urls[f] && (
                <Button size="sm" variant="outline" asChild>
                  <a href={urls[f]} download>
                    <Download className="h-3.5 w-3.5" /> {t("common.download")}
                  </a>
                </Button>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {!summary?.has_data && <div className="text-sm text-muted-foreground">{t("common.no_data")}</div>}

      {summary?.has_data && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>{t("reports_page.preview")} — {summary.filename}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-3">
            <DefconGauge defcon={summary.defcon} />
            <div className="md:col-span-2">
              <div className="mono grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <span>Packets</span><b>{summary.total_packets.toLocaleString()}</b>
                <span>Volume</span><b>{summary.summary_stats.Total_Bytes_Formatted}</b>
                <span>Duration</span><b>{summary.summary_stats.Duration_Seconds.toFixed(2)} s</b>
                <span>Rate</span><b>{summary.summary_stats.Packet_Rate} / {summary.summary_stats.Data_Rate_Kbps}</b>
                <span>Endpoints</span><b>{summary.ip_profiles.length}</b>
                <span>Carved files</span><b>{summary.carved.length}</b>
              </div>
              <div className="mt-2 space-y-1">
                {summary.threats.slice(0, 4).map((th) => (
                  <div key={th.id} className="flex items-center gap-2 border-b py-1 text-[11px]">
                    <SeverityBadge severity={th.severity} />
                    <span className="font-medium">{th.title}</span>
                    <span className="mono ms-auto text-muted-foreground">{th.mitre_id}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
