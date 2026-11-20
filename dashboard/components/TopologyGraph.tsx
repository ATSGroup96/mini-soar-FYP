"use client";
import { useEffect, useRef } from "react";

type Node = { id: string; label: string; type: string; risk?: number; [k: string]: any };
type Graph = {
  nodes: Node[];
  edges: { source: string; target: string; kind: string }[];
};

function riskColor(r = 0) {
  if (r >= 80) return "#ef4444";
  if (r >= 60) return "#f97316";
  if (r >= 40) return "#eab308";
  if (r > 0) return "#22c55e";
  return "#64748b";
}

const EDGE_COLOR: Record<string, string> = {
  has: "#475569", data: "#f97316", interaction: "#38bdf8", network: "#a855f7",
};

export default function TopologyGraph({ graph, onSelect }: {
  graph: Graph; onSelect?: (n: Node | null) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cy: any;
    let cancelled = false;
    (async () => {
      const cytoscape = (await import("cytoscape")).default;
      if (cancelled || !ref.current) return;
      const ids = new Set(graph.nodes.map((n) => n.id));
      cy = cytoscape({
        container: ref.current,
        elements: [
          ...graph.nodes.map((n) => ({ data: { ...n, risk: n.risk ?? 0 } })),
          ...graph.edges
            .filter((e) => ids.has(e.source) && ids.has(e.target))
            .map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, kind: e.kind } })),
        ],
        style: [
          {
            selector: "node",
            style: {
              label: "data(label)", color: "#e5edff", "font-size": 9,
              "text-valign": "bottom", "text-margin-y": 5,
              width: 22, height: 22,
              "background-color": (ele: any) => riskColor(ele.data("risk")),
              "border-width": 2, "border-color": "#0b0f17",
            },
          },
          {
            selector: 'node[type="host"]',
            style: { shape: "round-rectangle", width: 46, height: 46, "font-size": 11 },
          },
          {
            selector: 'node[type="os"]',
            style: { shape: "hexagon", width: 28, height: 28 },
          },
          { selector: "node[?rogue]", style: { "border-color": "#ef4444", "border-width": 4 } },
          {
            selector: "edge",
            style: {
              width: (ele: any) => (ele.data("kind") === "has" ? 1 : 2),
              "line-color": (ele: any) => EDGE_COLOR[ele.data("kind")] || "#64748b",
              "target-arrow-color": (ele: any) => EDGE_COLOR[ele.data("kind")] || "#64748b",
              "target-arrow-shape": (ele: any) => (ele.data("kind") === "has" ? "none" : "triangle"),
              "curve-style": "bezier",
              "line-style": (ele: any) => (ele.data("kind") === "network" ? "dashed" : "solid"),
            },
          },
        ],
        layout: { name: "cose", animate: false, padding: 30 },
      });
      cy.on("tap", "node", (evt: any) => onSelect?.(evt.target.data()));
      cy.on("tap", (evt: any) => { if (evt.target === cy) onSelect?.(null); });
    })();
    return () => {
      cancelled = true;
      if (cy) cy.destroy();
    };
  }, [graph, onSelect]);

  return <div ref={ref} className="w-full h-[520px] rounded-lg bg-base border border-edge" />;
}
