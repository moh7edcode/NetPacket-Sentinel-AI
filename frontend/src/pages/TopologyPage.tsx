import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Network } from "lucide-react";
import { api } from "@/services/api";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { ForceGraph } from "@/components/topology/ForceGraph";
import { IpDrilldown } from "@/components/topology/IpDrilldown";

export default function TopologyPage() {
  const { t } = useTranslation();
  const { data: topo } = useQuery({ queryKey: ["topology"], queryFn: api.topology });
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <div className="space-y-2">
      <PageHeader
        icon={Network}
        title={t("topology_page.title")}
        hint={`${topo?.nodes.length ?? 0} ${t("topology_page.nodes")} · ${topo?.links.length ?? 0} ${t("topology_page.links")} — ${t("topology_page.hint")}`}
      />
      <Card>
        <CardContent className="p-0">
          <ForceGraph
            nodes={topo?.nodes ?? []}
            links={topo?.links ?? []}
            height={Math.max(420, window.innerHeight - 230)}
            onNodeClick={setSelected}
          />
        </CardContent>
      </Card>
      <div className="flex gap-4 text-[11px] text-muted-foreground">
        <span><span className="me-1 inline-block h-2 w-2 rounded-full bg-[#ef4444]" />{t("topology_page.legend_malicious")}</span>
        <span><span className="me-1 inline-block h-2 w-2 rounded-full bg-[#f97316]" />{t("topology_page.legend_suspicious")}</span>
        <span><span className="me-1 inline-block h-2 w-2 rounded-full bg-[#10b981]" />{t("topology_page.legend_safe")}</span>
        <span><span className="me-1 inline-block h-2 w-2 rounded-full bg-[#00f3ff]" />{t("topology_page.legend_external")}</span>
      </div>
      <IpDrilldown ip={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
