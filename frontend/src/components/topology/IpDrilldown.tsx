import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "@/services/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";

export function IpDrilldown({ ip, onClose }: { ip: string | null; onClose: () => void }) {
  const { t } = useTranslation();
  const { data } = useQuery({
    queryKey: ["ip-inspect", ip],
    queryFn: () => api.ip(ip!),
    enabled: !!ip,
  });

  return (
    <Dialog open={!!ip} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-4xl">
        {data && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-3">
                <span className="mono">{data.ip}</span>
                <span className="rounded-full px-2.5 py-0.5 text-xs font-bold"
                  style={{ color: data.defcon.color, border: `1px solid ${data.defcon.color}` }}>
                  {data.defcon.status} · score {data.defcon.score}
                </span>
              </DialogTitle>
            </DialogHeader>
            <div className="grid gap-3 md:grid-cols-2 text-[12px]">
              <section>
                <h4 className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">Geo / ASN</h4>
                <div className="mono rounded-md border bg-muted/40 p-2 leading-relaxed">
                  {data.geo.Country} ({data.geo.Country_Code}) · {data.geo.City}<br />
                  {data.geo.ISP} · {data.geo.ASN}<br />
                  {data.geo.Reverse_DNS !== "N/A" ? <span>RDNS: {data.geo.Reverse_DNS}</span> : null}
                  {data.geo.Domain_Names?.length ? <div>Domains: {data.geo.Domain_Names.join(", ")}</div> : null}
                </div>
              </section>
              <section>
                <h4 className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">VirusTotal</h4>
                <div className="rounded-md border bg-muted/40 p-2">
                  <span className="mono font-bold">{data.vt.Verdict}</span>
                  <span className="ms-2">malicious {data.vt.Malicious_Count ?? 0} / suspicious {data.vt.Suspicious_Count ?? 0}</span>
                  {data.vt.Reputation_Score != null && (
                    <span className="ms-2 text-muted-foreground">score {data.vt.Reputation_Score}</span>
                  )}
                </div>
              </section>
              <section>
                <h4 className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">
                  {t("topology_page.peers")} ({data.peers.length})
                </h4>
                <div className="max-h-40 overflow-y-auto rounded-md border">
                  <table className="mono w-full text-[11px]">
                    <thead className="bg-muted/60 text-muted-foreground">
                      <tr>
                        <th className="p-1.5 text-start">Peer</th>
                        <th className="p-1.5 text-end">TX</th>
                        <th className="p-1.5 text-end">RX</th>
                        <th className="p-1.5 text-end">Bytes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.peers.map((p) => (
                        <tr key={p.peer} className="border-t">
                          <td className="p-1.5">{p.peer}</td>
                          <td className="p-1.5 text-end">{p.packets_tx}</td>
                          <td className="p-1.5 text-end">{p.packets_rx}</td>
                          <td className="p-1.5 text-end">{p.bytes_fmt}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
              <section>
                <h4 className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">
                  {t("topology_page.ports")} ({data.port_footprint.length})
                </h4>
                <div className="max-h-40 overflow-y-auto rounded-md border">
                  {data.port_footprint.slice(0, 12).map((pf, i) => (
                    <div key={i} className="mono flex justify-between border-t px-2 py-1 text-[11px] first:border-t-0">
                      <span>{pf.protocol}/{pf.port}</span>
                      <span className="text-muted-foreground">{pf.role}</span>
                      <span>{pf.count}×</span>
                    </div>
                  ))}
                </div>
              </section>
              <section>
                <h4 className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">
                  {t("dashboard.threats")} ({data.threats.length})
                </h4>
                <div className="max-h-40 space-y-1 overflow-y-auto">
                  {data.threats.map((th, i) => (
                    <div key={i} className="rounded-md border bg-muted/40 px-2 py-1">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={th.severity} />
                        <span className="mono text-[10px] text-muted-foreground">{th.mitre_id}</span>
                      </div>
                      <div className="mt-0.5 text-[11px] font-medium">{th.title}</div>
                      <div className="text-[10px] text-muted-foreground">{th.role}</div>
                    </div>
                  ))}
                  {data.threats.length === 0 && <div className="text-[11px] text-muted-foreground">No alerts involve this IP.</div>}
                </div>
              </section>
              <section>
                <h4 className="mb-1 text-[11px] uppercase tracking-wider text-muted-foreground">
                  {t("topology_page.carved_for")} ({data.carved.length})
                </h4>
                <div className="flex flex-wrap gap-1">
                  {data.carved.map((c) => (
                    <Badge key={c.File_ID} variant="secondary" className="mono text-[10px]">
                      {c.Filename} · {c.File_Type}
                    </Badge>
                  ))}
                  {data.carved.length === 0 && <span className="text-[11px] text-muted-foreground">—</span>}
                </div>
              </section>
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
