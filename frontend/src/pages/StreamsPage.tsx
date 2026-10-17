import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Activity, Terminal } from "lucide-react";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/layout/PageHeader";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { STREAM_TEXT, formatBytes } from "@/lib/utils";

function DecoderSandbox() {
  const { t } = useTranslation();
  const [text, setText] = useState("VGhpcyBpcyBhIEJhc2U2NCBlbmNvZGVkIENyZWRlbnRpYWw=");
  const [isHex, setIsHex] = useState(false);
  const [res, setRes] = useState<Awaited<ReturnType<typeof api.decode>> | null>(null);

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2"><Terminal className="h-4 w-4 text-primary" />{t("streams_page.decoder")}</CardTitle>
        <p className="text-[11px] text-muted-foreground">{t("streams_page.decoder_hint")}</p>
      </CardHeader>
      <CardContent className="space-y-2">
        <Input value={text} onChange={(e) => setText(e.target.value)} className="mono text-xs" />
        <div className="flex items-center gap-3">
          <Label className="flex items-center gap-2 text-xs">
            <Switch checked={isHex} onCheckedChange={setIsHex} /> Hex input
          </Label>
          <Button size="sm" onClick={() => api.decode(text, isHex).then(setRes)}>{t("streams_page.decode")}</Button>
          {res?.success && (
            <span className="mono text-xs">
              entropy {res.entropy?.toFixed(2)} {res.is_high_entropy && <span className="text-threat">⚠ high</span>}
            </span>
          )}
        </div>
        {res?.success && (res.decodings ?? []).map((d, i) => (
          <div key={i} className="rounded-md border bg-muted/30 p-2">
            <div className="flex justify-between">
              <span className="mono text-[11px] font-bold text-primary">{d.Type}</span>
              <span className="mono text-[11px] text-muted-foreground">{Math.round(d.Confidence * 100)}%</span>
            </div>
            <div className="mono mt-1 break-all text-[11px]">{d.Result}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export default function StreamsPage() {
  const { t } = useTranslation();
  const { data: streams } = useQuery({ queryKey: ["streams-list"], queryFn: api.streams });

  return (
    <div className="space-y-0">
      <PageHeader icon={Activity} title={t("nav.streams")} count={streams?.length ?? 0} />
      <div className="grid gap-3 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader className="pb-2">
          <CardTitle>{t("streams_page.title")}</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="max-h-[60vh] overflow-auto">
            <table className="mono w-full text-[11px]">
              <thead className="sticky top-0 bg-muted/80 text-muted-foreground backdrop-blur">
                <tr>
                  <th className="p-2 text-start">{t("common.source")}</th>
                  <th className="p-2 text-start">{t("common.destination")}</th>
                  <th className="p-2 text-start">{t("common.protocol")}</th>
                  <th className="p-2 text-end">{t("common.packets")}</th>
                  <th className="p-2 text-end">{t("common.bytes")}</th>
                  <th className="p-2 text-start">Payload Preview</th>
                </tr>
              </thead>
              <tbody>
                {(streams ?? []).map((s, i) => (
                  <tr key={i} className="border-t">
                    <td className={`p-2 ${STREAM_TEXT.client}`}>{s.Client}</td>
                    <td className={`p-2 ${STREAM_TEXT.server}`}>{s.Server}</td>
                    <td className="p-2">{s.Protocol}</td>
                    <td className="p-2 text-end">{s.Packet_Count}</td>
                    <td className="p-2 text-end">{formatBytes(s.Total_Bytes)}</td>
                    <td className="max-w-[280px] truncate p-2 text-muted-foreground" title={`${s.Client_Payload_Preview}\n${s.Server_Payload_Preview}`}>
                      {s.Client_Payload_Preview || s.Server_Payload_Preview || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
      <div className="space-y-3">
        <DecoderSandbox />
        <Card>
          <CardContent className="py-4 text-[11px] text-muted-foreground">
            Client → traffic is cyan, server ← replies are indigo. Open{" "}
            <a href="/dissector" className="text-primary hover:underline">{t("nav.dissector")}</a>{" "}
            and use “Follow Stream” on any packet for full bidirectional reassembly.
          </CardContent>
        </Card>
      </div>
      </div>
    </div>
  );
}
