"use client";
import { useEffect, useRef } from "react";

type Graph = {
  nodes: { id: string; label: string; type: string; risk?: number; grade?: string }[];
  edges: { source: string; target: string; kind: string }[];
};

function riskColor(r = 0, type = "host") {
  if (type === "attacker") return "#ef4444";
  if (r >= 80) return "#ef4444";
  if (r >= 60) return "#f97316";
  if (r >= 40) return "#eab308";
  return "#22c55e";
}

export default function TopologyGraph({ graph }: { graph: Graph }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cy: any;
    let cancelled = false;
    (async () => {
      const cytoscape = (await import("cytoscape")).default;
      if (cancelled || !ref.current) return;
      cy = cytoscape({
        container: ref.current,
        elements: [
          ...graph.nodes.map((n) => ({
            data: { id: n.id, label: n.label, risk: n.risk ?? 0, type: n.type },
          })),
          ...graph.edges.map((e, i) => ({
            data: { id: `e${i}`, source: e.source, target: e.target, kind: e.kind },
          })),
        ],
        style: [
          {
            selector: "node",
            style: {
              label: "data(label)",
              color: "#e5edff",
              "font-size": 10,
              "text-valign": "bottom",
              "text-margin-y": 6,
              width: 42,
              height: 42,
              "background-color": (ele: any) =>
                riskColor(ele.data("risk"), ele.data("type")),
              "border-width": 2,
              "border-color": "#0b0f17",
            },
          },
          {
            selector: 'node[type="attacker"]',
            style: { shape: "diamond", width: 50, height: 50 },
          },
          {
            selector: "edge",
            style: {
              width: 2,
              "line-color": (ele: any) =>
                ele.data("kind") === "initial-access" ? "#ef4444" : "#f97316",
              "target-arrow-color": "#8ea0c0",
              "target-arrow-shape": "triangle",
              "curve-style": "bezier",
              "line-style": (ele: any) =>
                ele.data("kind") === "lateral-movement" ? "dashed" : "solid",
            },
          },
        ],
        layout: { name: "cose", animate: false, padding: 30 },
      });
    })();
    return () => {
      cancelled = true;
      if (cy) cy.destroy();
    };
  }, [graph]);

  return <div ref={ref} className="w-full h-[480px] rounded-lg bg-base border border-edge" />;
}
