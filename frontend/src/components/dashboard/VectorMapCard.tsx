import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Share2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ForceGraph } from "@/components/topology/ForceGraph";
import type { AiData, TopoLink, TopoNode } from "@/services/types";

export function VectorMapCard({ ai }: { ai?: AiData }) {
  const { t } = useTranslation();
  const vm = ai?.vector_map;

  const { nodes, links } = useMemo(() => {
    if (!vm?.links?.length) return { nodes: [] as TopoNode[], links: [] as TopoLink[] };
    const map = new Map<string, TopoNode>();
    const add = (id: string, threat: "MALICIOUS" | "SUSPICIOUS" | "EXTERNAL", color: string) => {
      if (!map.has(id)) {
        map.set(id, {
          id, label: id, color, packets: 0, threat_level: threat, threat_score: 0,
          is_private: threat === "SUSPICIOUS", country: "", isp: "", bytes: 0,
        });
      }
    };
    vm.attackers.forEach((ip) => add(ip, "MALICIOUS", "#ef4444"));
    vm.benign.forEach((ip) => add(ip, "SUSPICIOUS", "#10b981"));
    vm.links.forEach((l) => {
      add(l.source, vm.attackers.includes(l.source) ? "MALICIOUS" : "SUSPICIOUS",
        vm.attackers.includes(l.source) ? "#ef4444" : "#10b981");
      add(l.target, "EXTERNAL", "#00f3ff");
      const n = map.get(map.has(l.source) ? l.source : l.target);
      if (n) n.packets += l.count;
    });
    return {
      nodes: [...map.values()],
      links: vm.links.map((l) => ({ source: l.source, target: l.target, protocol: l.decision, packets: l.count, bytes: 0 })),
    };
  }, [vm]);

  return (
    <Card className="h-full">
      <CardHeader className="pb-1">
        <CardTitle className="flex items-center gap-2">
          <Share2 className="h-4 w-4 text-primary" />{t("dashboard.vector_map")}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {nodes.length === 0 ? (
          <div className="py-10 text-center text-xs text-muted-foreground">{t("dashboard.no_vector_data")}</div>
        ) : (
          <ForceGraph nodes={nodes} links={links} height={220} />
        )}
      </CardContent>
    </Card>
  );
}
