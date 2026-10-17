import { useEffect, useMemo, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { ChevronDown, ChevronRight, Search } from "lucide-react";
import { api } from "@/services/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { SeverityBadge } from "@/components/SeverityBadge";
import { formatBytes } from "@/lib/utils";
import type { PacketDetail, PacketSummary } from "@/services/types";

const PROTO_COLOR: Record<string, string> = {
  DNS: "text-sky-500",
  HTTP: "text-amber-600 dark:text-amber-400",
  TLS: "text-violet-500",
  TCP: "",
  UDP: "text-emerald-500",
  ICMP: "text-rose-400",
  ARP: "text-orange-400",
};

function LayerNode({ name, value }: { name: string; value: unknown }) {
  const [open, setOpen] = useState(false);
  const isObj = typeof value === "object" && value !== null;
  return (
    <div className="ms-2">
      <button
        className="flex w-full items-start gap-1 text-start hover:bg-accent/30"
        onClick={() => isObj && setOpen((o) => !o)}
      >
        {isObj ? (open ? <ChevronDown className="mt-0.5 h-3 w-3 shrink-0" /> : <ChevronRight className="mt-0.5 h-3 w-3 shrink-0" />) : <span className="w-3 shrink-0" />}
        <span className="mono text-[11px]">
          <span className="font-semibold text-primary">{name}:</span>{" "}
          {!isObj && <span className="break-all">{String(value)}</span>}
        </span>
      </button>
      {isObj && open && (
        <div>
          {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
            <LayerNode key={k} name={k} value={v} />
          ))}
        </div>
      )}
      {isObj && !open && (
        <div className="ms-4 mono text-[10px] text-muted-foreground">
          {Object.keys(value as object).slice(0, 6).join(", ")}
          {Object.keys(value as object).length > 6 ? "…" : ""}
        </div>
      )}
    </div>
  );
}

export function ProtocolTree({ detail }: { detail: PacketDetail }) {
  return (
    <div className="space-y-1">
      {detail.layers.map((layer, i) =>
        Object.entries(layer).map(([name, value]) => (
          <LayerNode key={`${i}-${name}`} name={name} value={value} />
        )),
      )}
    </div>
  );
}

export function usePacketList() {
  const [query, setQuery] = useState("");
  const [committed, setCommitted] = useState("");
  const [rows, setRows] = useState<PacketSummary[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);
  const PAGE = 1000;

  const loadFrom = useMemo(
    () => async (offset: number) => {
      setLoading(true);
      const d = await api.packets(offset, PAGE, committed);
      setRows((prev) => (offset === 0 ? d.packets : [...prev, ...d.packets]));
      setTotal(d.total_packets);
      setHasMore(offset + d.packets.length < d.total_packets);
      setLoading(false);
    },
    [committed],
  );

  const initial = useQuery({
    queryKey: ["packets-init", committed],
    queryFn: () => api.packets(0, PAGE, committed),
  });

  useEffect(() => {
    if (initial.data) {
      setRows(initial.data.packets);
      setTotal(initial.data.total_packets);
      setHasMore(initial.data.packets.length < initial.data.total_packets);
    }
  }, [initial.data]);

  return {
    rows,
    total: total ?? initial.data?.total_packets ?? 0,
    loading,
    hasMore,
    loadMore: () => {
      if (!loading && hasMore) void loadFrom(rows.length);
    },
    applyQuery: (q: string) => {
      setCommitted(q);
    },
    query,
    setQuery,
    committed,
  };
}

export function PacketTable({
  rows,
  onSelect,
  selected,
  list,
}: {
  rows: PacketSummary[];
  selected: number | null;
  onSelect: (n: number) => void;
  list: ReturnType<typeof usePacketList>;
}) {
  const { t } = useTranslation();
  const parentRef = useMemo(() => ({ current: null as HTMLDivElement | null }), []);
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 26,
    overscan: 20,
  });

  return (
    <div className="flex h-full flex-col">
      <div className="flex gap-2 p-2">
        <Input
          value={list.query}
          placeholder={t("dissector.filter_placeholder")}
          onChange={(e) => list.setQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && list.applyQuery(list.query)}
          className="mono text-xs"
        />
        <Button size="sm" variant="outline" onClick={() => list.applyQuery(list.query)}>
          <Search className="h-3.5 w-3.5" />
        </Button>
      </div>
      <div ref={parentRef} className="mono flex-1 overflow-auto text-[11px]">
        <div style={{ height: virt.getTotalSize(), position: "relative" }}>
          {virt.getVirtualItems().map((row) => {
            const p = rows[row.index];
            if (row.index >= rows.length - 40) list.loadMore();
            return (
              <div
                key={p.num}
                onClick={() => onSelect(p.num)}
                style={{
                  position: "absolute",
                  top: row.start,
                  height: row.size,
                  left: 0,
                  right: 0,
                }}
                className={`flex cursor-pointer items-center gap-2 border-b border-border/40 px-2 hover:bg-accent/40 ${
                  selected === p.num ? "bg-accent" : PROTO_COLOR[p.protocol] ?? ""
                }`}
              >
                <span className="w-12 shrink-0 tabular-nums">{p.num}</span>
                <span className="w-16 shrink-0 tabular-nums">{p.time.slice(0, 8)}</span>
                <span className="w-32 truncate">{p.src}</span>
                <span className="w-32 truncate">{p.dst}</span>
                <span className="w-14 shrink-0">{p.proto}</span>
                <span className="w-12 shrink-0 tabular-nums text-end">{p.length}</span>
                <span className="truncate text-muted-foreground">{p.info}</span>
              </div>
            );
          })}
        </div>
      </div>
      <div className="border-t px-2 py-1 text-[10px] text-muted-foreground">
        {rows.length.toLocaleString()} / {list.total.toLocaleString()} {t("common.packets")}
        {list.loading && " · loading…"}
      </div>
    </div>
  );
}

export { SeverityBadge, formatBytes };
