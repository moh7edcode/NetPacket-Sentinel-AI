import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ArrowLeftRight, ScanLine, ScanSearch } from "lucide-react";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { IpDrilldown } from "@/components/topology/IpDrilldown";
import { STREAM_BG } from "@/lib/utils";
import {
  PacketTable,
  ProtocolTree,
  usePacketList,
} from "@/components/dissector/dissectorParts";

function StreamDialog({ packetNum, onClose }: { packetNum: number | null; onClose: () => void }) {
  const { t } = useTranslation();
  const { data } = useQuery({
    queryKey: ["follow", packetNum],
    queryFn: () => api.followStream(packetNum!),
    enabled: !!packetNum,
  });
  return (
    <Dialog open={!!packetNum} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="mono text-sm">
            {data ? `${data.client} ⇄ ${data.server} · ${data.total_packets} pkts · ${data.duration}s` : t("streams_page.title")}
          </DialogTitle>
        </DialogHeader>
        <div className="max-h-[55vh] space-y-1 overflow-y-auto rounded-md border bg-muted/30 p-2">
          {(data?.chunks ?? []).map((c, i) => {
            const isClient = c.sender === data!.client;
            return (
              <div key={i} className={`mono whitespace-pre-wrap rounded px-2 py-1 text-[11px] ${isClient ? STREAM_BG.client : STREAM_BG.server}`}>
                <span className="me-2 text-muted-foreground">
                  #{c.packet_num} t+{c.rel_time}s {isClient ? "→" : "←"}
                </span>
                {c.text || c.hex}
              </div>
            );
          })}
          {data && data.chunks.length === 0 && (
            <div className="text-[12px] text-muted-foreground">Stream has no payload chunks (pure TCP handshake / ACKs).</div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function HexPane({ detail }: { detail: Awaited<ReturnType<typeof api.packet>> }) {
  const { t } = useTranslation();
  const maxE = 8;
  return (
    <div className="flex h-full flex-col">
      <div className="mb-1 flex items-center gap-2">
        <span className="text-[10px] uppercase text-muted-foreground">{t("dissector.entropy")}</span>
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
          <div
            className={`h-full rounded-full ${detail.is_high_entropy ? "bg-threat" : "bg-primary"}`}
            style={{ width: `${Math.min(100, (detail.entropy / maxE) * 100)}%` }}
          />
        </div>
        <span className={`mono text-[11px] font-bold ${detail.is_high_entropy ? "text-threat" : ""}`}>
          {detail.entropy.toFixed(2)} {detail.is_high_entropy && "⚠ obfuscated?"}
        </span>
      </div>
      <pre className="mono flex-1 overflow-auto whitespace-pre rounded-md border bg-muted/30 p-2 text-[10px] leading-[1.4]">
        {detail.hex_dump}
      </pre>
      <div className="mt-1 flex items-start gap-2 text-[10px]">
        <span className="shrink-0 uppercase text-muted-foreground">ASCII</span>
        <pre className="mono max-h-16 flex-1 overflow-auto whitespace-pre text-muted-foreground">{detail.ascii_text}</pre>
      </div>
      {detail.decodings.length > 0 && (
        <div className="mt-1 border-t pt-1">
          <div className="mb-0.5 text-[10px] uppercase text-muted-foreground">{t("dissector.decoded")}</div>
          {detail.decodings.map((d, i) => (
            <div key={i} className="mono flex gap-2 text-[10px]">
              <span className="w-16 font-bold text-primary">{d.Type}</span>
              <span className="text-muted-foreground">{Math.round(d.Confidence * 100)}%</span>
              <span className="truncate">{d.Result}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function DissectorPage() {
  const { t } = useTranslation();
  const list = usePacketList();
  const [selected, setSelected] = useState<number | null>(1);
  const [followNum, setFollowNum] = useState<number | null>(null);
  const [inspectIp, setInspectIp] = useState<string | null>(null);

  const { data: detail } = useQuery({
    queryKey: ["packet-detail", selected],
    queryFn: () => api.packet(selected!),
    enabled: !!selected,
  });

  return (
    <div className="flex h-full flex-col gap-2">
      <PageHeader icon={ScanLine} title={t("nav.dissector")} />
      <div className="grid flex-1 grid-rows-[2fr_3fr] gap-2 overflow-hidden lg:grid-cols-2 lg:grid-rows-2">
        <Card className="overflow-hidden lg:col-span-2 lg:row-span-1">
          <CardContent className="p-0">
            <PacketTable rows={list.rows} selected={selected} onSelect={setSelected} list={list} />
          </CardContent>
        </Card>
        <Card className="overflow-hidden">
          <CardHeader className="flex-row items-center justify-between py-2">
            <CardTitle>{t("dissector.tree")}{selected ? ` · #${selected}` : ""}</CardTitle>
            <div className="flex gap-1">
              <Button size="sm" variant="outline" onClick={() => setFollowNum(selected)} disabled={!selected}>
                <ArrowLeftRight className="h-3.5 w-3.5" /> {t("dissector.follow")}
              </Button>
              <Button size="sm" variant="outline" onClick={() => detail && setInspectIp(detail.src)} disabled={!detail}>
                <ScanSearch className="h-3.5 w-3.5" /> {t("dissector.inspect_ip")}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="max-h-[36vh] overflow-y-auto">
            {detail ? <ProtocolTree detail={detail} /> : <Skeleton className="h-20" />}
          </CardContent>
        </Card>
        <Card className="overflow-hidden">
          <CardHeader className="py-2"><CardTitle>{t("dissector.hex")}</CardTitle></CardHeader>
          <CardContent className="h-[calc(100%-2.5rem)]">
            {detail ? (
              <Tabs defaultValue="hex" className="h-full">
                <TabsList className="h-7">
                  <TabsTrigger value="hex">Hex</TabsTrigger>
                  <TabsTrigger value="ascii">ASCII</TabsTrigger>
                </TabsList>
                <TabsContent value="hex" className="h-[32vh]">{<HexPane detail={detail} />}</TabsContent>
                <TabsContent value="ascii" className="h-[32vh]">
                  <pre className="mono max-h-[32vh] overflow-auto whitespace-pre rounded-md border bg-muted/30 p-2 text-[10px]">
                    {detail.raw_payload_text}
                  </pre>
                </TabsContent>
              </Tabs>
            ) : (
              <Skeleton className="h-20" />
            )}
          </CardContent>
        </Card>
      </div>
      {!detail && (
        <div className="text-center text-xs text-muted-foreground">{t("dissector.no_selection")}</div>
      )}
      <StreamDialog packetNum={followNum} onClose={() => setFollowNum(null)} />
      <IpDrilldown ip={inspectIp} onClose={() => setInspectIp(null)} />
    </div>
  );
}
