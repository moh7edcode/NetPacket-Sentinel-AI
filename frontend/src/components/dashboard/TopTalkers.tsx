import { useTranslation } from "react-i18next";
import { ArrowLeftRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatBytes } from "@/lib/utils";
import type { TopoLink } from "@/services/types";

export function TopTalkers({ links }: { links: TopoLink[] }) {
  const { t } = useTranslation();
  const pairs = [...links]
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 7);

  return (
    <Card className="h-full">
      <CardHeader className="pb-1">
        <CardTitle className="flex items-center gap-2"><ArrowLeftRight className="h-4 w-4 text-primary" />{t("dashboard.top_talkers")}</CardTitle>
      </CardHeader>
      <CardContent className="p-2">
        <table className="mono w-full text-[11px]">
          <thead className="text-muted-foreground">
            <tr>
              <th className="text-start font-medium">{t("common.source")}</th>
              <th className="text-start font-medium">{t("common.destination")}</th>
              <th className="text-end font-medium">{t("common.protocol")}</th>
              <th className="text-end font-medium">{t("common.bytes")}</th>
            </tr>
          </thead>
          <tbody>
            {pairs.map((l, i) => (
              <tr key={i} className="border-t border-dashed border-border">
                <td className="py-1">{l.source}</td>
                <td className="py-1">{l.target}</td>
                <td className="py-1 text-end">{l.protocol}</td>
                <td className="py-1 text-end">{formatBytes(l.bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
