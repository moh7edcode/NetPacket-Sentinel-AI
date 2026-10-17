import { useEffect, useMemo, useState } from "react";
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationNodeDatum,
} from "d3-force";
import type { TopoLink, TopoNode } from "@/services/types";

interface SimNode extends SimulationNodeDatum {
  id: string;
  raw: TopoNode;
}
interface SimLink {
  source: SimNode | string;
  target: SimNode | string;
  packets: number;
  protocol: string;
}

export function ForceGraph({
  nodes,
  links,
  height = 480,
  onNodeClick,
  mini = false,
}: {
  nodes: TopoNode[];
  links: TopoLink[];
  height?: number;
  onNodeClick?: (id: string) => void;
  mini?: boolean;
}) {
  const [size, setSize] = useState({ w: 600, h: height });
  const [hover, setHover] = useState<string | null>(null);

  useEffect(() => {
    const el = document.getElementById("fg-wrap");
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth, h: height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [height]);

  const layout = useMemo(() => {
    if (!nodes.length) return { ns: [] as SimNode[], ls: [] as SimLink[] };
    const ns: SimNode[] = nodes.map((n) => ({ id: n.id, raw: n }));
    const ls: SimLink[] = links.map((l) => ({ source: l.source, target: l.target, packets: l.packets, protocol: l.protocol }));
    const sim = forceSimulation(ns)
      .force("link", forceLink<SimNode, SimLink>(ls).id((d) => d.id).distance(mini ? 46 : 90).strength(0.5))
      .force("charge", forceManyBody().strength(mini ? -80 : -220))
      .force("center", forceCenter(size.w / 2, size.h / 2))
      .force("collide", forceCollide(mini ? 10 : 22))
      .stop();
    const ticks = Math.min(300, Math.max(120, ns.length * 8));
    for (let i = 0; i < ticks; i++) sim.tick();
    ns.forEach((n) => {
      n.x = Math.max(14, Math.min(size.w - 14, n.x ?? size.w / 2));
      n.y = Math.max(14, Math.min(size.h - 14, n.y ?? size.h / 2));
    });
    return { ns, ls };
  }, [nodes, links, size.w, size.h, mini]);

  const pos = useMemo(() => {
    const m = new Map<string, { x: number; y: number }>();
    layout.ns.forEach((n) => m.set(n.id, { x: n.x ?? 0, y: n.y ?? 0 }));
    return m;
  }, [layout]);

  const byId = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  return (
    <div id="fg-wrap" className="relative w-full" style={{ height }}>
      <svg width={size.w} height={size.h} className="block">
        <style>{`
          @keyframes dashmove { to { stroke-dashoffset: -14; } }
          .pulse-link { animation: dashmove 0.9s linear infinite; }
        `}</style>
        {layout.ls.map((l, i) => {
          const srcId = typeof l.source === "string" ? l.source : l.source.id;
          const tgtId = typeof l.target === "string" ? l.target : l.target.id;
          const s = typeof l.source === "string" ? pos.get(l.source) : { x: (l.source as SimNode).x, y: (l.source as SimNode).y };
          const t = typeof l.target === "string" ? pos.get(l.target) : { x: (l.target as SimNode).x, y: (l.target as SimNode).y };
          if (!s || !t) return null;
          const active = hover && (srcId === hover || tgtId === hover);
          return (
            <line
              key={i}
              x1={s.x} y1={s.y} x2={t.x} y2={t.y}
              stroke={active ? "#22d3ee" : "hsl(var(--border))"}
              strokeWidth={active ? 2 : Math.min(2.5, 0.6 + Math.log2(1 + l.packets) / 2)}
              strokeDasharray={active ? "5 3" : undefined}
              className={active ? "pulse-link" : undefined}
            />
          );
        })}
        {layout.ns.map((n) => {
          const raw = byId.get(n.id);
          const r = mini ? 5 : Math.min(18, 6 + Math.log2(1 + (raw?.packets ?? 1)) * 1.6);
          const malicious = raw?.threat_level === "MALICIOUS";
          return (
            <g
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              className="cursor-pointer"
              onMouseEnter={() => setHover(n.id)}
              onMouseLeave={() => setHover(null)}
              onClick={() => onNodeClick?.(n.id)}
            >
              {malicious && !mini && (
                <circle r={r + 6} fill={raw!.color} opacity={0.18} className="animate-pulse-glow" />
              )}
              <circle r={r} fill={raw?.color ?? "#64748b"} stroke="hsl(var(--background))" strokeWidth={1.5} />
              {!mini && (
                <text y={-r - 5} textAnchor="middle" className="fill-foreground font-mono" fontSize={10}>
                  {n.id}
                </text>
              )}
              {!mini && (
                <text y={r + 12} textAnchor="middle" fontSize={8} className="fill-muted-foreground font-mono">
                  {raw?.threat_level} · {raw?.packets}p
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {hover && !mini && byId.get(hover) && (
        <div className="pointer-events-none absolute inset-x-0 bottom-1 mx-auto w-fit rounded-md border bg-popover/90 px-3 py-1.5 text-[11px] backdrop-blur">
          <span className="mono font-bold">{hover}</span>
          <span className="ms-2 text-muted-foreground">
            {byId.get(hover)!.country} · {byId.get(hover)!.packets} packets · {byId.get(hover)!.threat_level}
          </span>
        </div>
      )}
    </div>
  );
}
