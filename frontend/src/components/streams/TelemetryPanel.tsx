import { useTranslation } from "react-i18next";
import { Radar } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SEVERITY_COLORS } from "@/lib/utils";
import type { AiData } from "@/services/types";

function flagColor(flag: string): string {
  if (flag.includes("CRITICAL")) return SEVERITY_COLORS.CRITICAL;
  if (flag === "HIGH") return SEVERITY_COLORS.HIGH;
  if (flag === "MEDIUM") return SEVERITY_COLORS.MEDIUM;
  return "hsl(var(--muted-foreground))";
}

export function TelemetryPanel({ ai }: { ai?: AiData }) {
  const { t } = useTranslation();
  const dns = ai?.dns_telemetry ?? [];
  const tls = ai?.tls_telemetry ?? [];
  const beacons = ai?.beaconing ?? [];
  if (!dns.length && !tls.length && !beacons.length) return null;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2">
          <Radar className="h-4 w-4 text-primary" />{t("streams_page.telemetry")}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="dns">
          <TabsList className="h-7">
            <TabsTrigger value="dns">DNS ({dns.length})</TabsTrigger>
            <TabsTrigger value="tls">TLS ({tls.length})</TabsTrigger>
            <TabsTrigger value="beacon">Beaconing ({beacons.length})</TabsTrigger>
          </TabsList>
          <TabsContent value="dns" className="max-h-56 overflow-y-auto rounded-md border">
            <table className="mono w-full text-[10px]">
              <thead className="sticky top-0 bg-muted/80 text-muted-foreground backdrop-blur">
                <tr>
                  <th className="p-1.5 text-end">#</th>
                  <th className="p-1.5 text-start">{t("topology_page.peers")}</th>
                  <th className="p-1.5 text-start">Query</th>
                  <th className="p-1.5 text-end">Entropy</th>
                  <th className="p-1.5 text-start">Flag</th>
                </tr>
              </thead>
              <tbody>
                {dns.map((d, i) => (
                  <tr key={i} className="border-t">
                    <td className="p-1.5 text-end text-muted-foreground">{d.packet_num}</td>
                    <td className="p-1.5">{d.client_ip}</td>
                    <td className="max-w-[220px] truncate p-1.5" title={d.query}>{d.query}</td>
                    <td className="p-1.5 text-end font-bold" style={{ color: flagColor(d.flag) }}>{d.entropy.toFixed(2)}</td>
                    <td className="p-1.5 font-semibold" style={{ color: flagColor(d.flag) }}>
                      {d.is_tunneling ? `⚠ ${d.flag}` : d.flag}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TabsContent>
          <TabsContent value="tls" className="max-h-56 overflow-y-auto rounded-md border">
            <table className="mono w-full text-[10px]">
              <thead className="sticky top-0 bg-muted/80 text-muted-foreground backdrop-blur">
                <tr>
                  <th className="p-1.5 text-end">#</th>
                  <th className="p-1.5 text-start">Client</th>
                  <th className="p-1.5 text-start">SNI</th>
                  <th className="p-1.5 text-start">Version</th>
                </tr>
              </thead>
              <tbody>
                {tls.map((r, i) => (
                  <tr key={i} className="border-t">
                    <td className="p-1.5 text-end text-muted-foreground">{r.packet_num}</td>
                    <td className="p-1.5">{r.src_ip}</td>
                    <td className="max-w-[240px] truncate p-1.5 font-semibold text-primary" title={r.sni}>{r.sni || "—"}</td>
                    <td className="p-1.5 text-muted-foreground">{r.version}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TabsContent>
          <TabsContent value="beacon" className="max-h-56 space-y-1 overflow-y-auto">
            {beacons.map((b, i) => (
              <div key={i} className="rounded-md border bg-muted/30 p-2 text-[11px]">
                <div className="mono flex flex-wrap items-center gap-2">
                  <span className="font-bold">{b.source_ip}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-bold text-threat">{b.destination_ip}:{b.destination_port}</span>
                  <span className="ms-auto text-muted-foreground">{b.flow_count} flows · CV {b.coefficient_variation}</span>
                </div>
                <div className="mono mt-0.5 text-[10px] text-threat">{b.verdict}</div>
                <div className="mono text-[10px] text-muted-foreground">
                  interval {b.mean_interval_sec}s ± {b.std_interval_sec}s
                </div>
              </div>
            ))}
            {beacons.length === 0 && <div className="p-2 text-[11px] text-muted-foreground">{t("streams_page.no_beaconing")}</div>}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
