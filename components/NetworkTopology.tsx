"use client";

import React, { useState, useMemo } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Server,
  Laptop,
  Wifi,
  ExternalLink,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  ArrowRight,
  Filter,
  Activity,
  Layers,
  Flame,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { Button, Chip, Swatch, cn } from "./ui";
import { ParsedPacket, ConversationFlow, Finding } from "@/lib/engine/types";
import { formatBytes } from "@/lib/utils/formatters";

interface NetworkTopologyProps {
  packets: ParsedPacket[];
  flows: ConversationFlow[];
  findings: Finding[];
}

interface TopologyNode {
  id: string;
  ip: string;
  mac?: string;
  role: "ATTACKER" | "VICTIM" | "GATEWAY" | "SERVER" | "CLIENT";
  packetsIn: number;
  packetsOut: number;
  bytesTotal: number;
  protocols: Set<string>;
  associatedFindings: Finding[];
  x: number;
  y: number;
}

interface TopologyEdge {
  id: string;
  source: string;
  target: string;
  packets: number;
  bytes: number;
  protocol: string;
  isMalicious: boolean;
}

export function NetworkTopology({ packets, flows, findings }: NetworkTopologyProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [roleFilter, setRoleFilter] = useState<string>("ALL");
  const [zoomLevel, setZoomLevel] = useState<number>(1);

  // Identify attacker & victim IPs from findings
  const { attackerIps, victimIps } = useMemo(() => {
    const attackers = new Set<string>();
    const victims = new Set<string>();

    for (const f of findings) {
      if (f.category === "ATTACK") {
        if (f.affected_ips && f.affected_ips.length > 0) {
          attackers.add(f.affected_ips[0]);
          if (f.affected_ips[1]) victims.add(f.affected_ips[1]);
        }
      } else if (f.category === "FAULT") {
        if (f.affected_ips) {
          for (const ip of f.affected_ips) victims.add(ip);
        }
      }
    }
    return { attackerIps: attackers, victimIps: victims };
  }, [findings]);

  // Build nodes and edges
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, TopologyNode>();
    const edgeMap = new Map<string, TopologyEdge>();

    // Scan flows and packets for IP nodes
    for (const pkt of packets) {
      if (pkt.source_ip) {
        if (!nodeMap.has(pkt.source_ip)) {
          nodeMap.set(pkt.source_ip, {
            id: pkt.source_ip,
            ip: pkt.source_ip,
            mac: pkt.source_mac,
            role: "CLIENT",
            packetsIn: 0,
            packetsOut: 0,
            bytesTotal: 0,
            protocols: new Set(),
            associatedFindings: [],
            x: 0,
            y: 0,
          });
        }
        const node = nodeMap.get(pkt.source_ip)!;
        node.packetsOut++;
        node.bytesTotal += pkt.length;
        node.protocols.add(pkt.protocol);
        if (!node.mac && pkt.source_mac) node.mac = pkt.source_mac;
      }

      if (pkt.destination_ip) {
        if (!nodeMap.has(pkt.destination_ip)) {
          nodeMap.set(pkt.destination_ip, {
            id: pkt.destination_ip,
            ip: pkt.destination_ip,
            mac: pkt.destination_mac,
            role: "CLIENT",
            packetsIn: 0,
            packetsOut: 0,
            bytesTotal: 0,
            protocols: new Set(),
            associatedFindings: [],
            x: 0,
            y: 0,
          });
        }
        const node = nodeMap.get(pkt.destination_ip)!;
        node.packetsIn++;
        node.bytesTotal += pkt.length;
        node.protocols.add(pkt.protocol);
        if (!node.mac && pkt.destination_mac) node.mac = pkt.destination_mac;
      }
    }

    // Assign roles & associated findings
    for (const [ip, node] of nodeMap.entries()) {
      node.associatedFindings = findings.filter(
        f => (f.affected_ips && f.affected_ips.includes(ip)) || f.technical_details.root_cause.includes(ip)
      );

      if (attackerIps.has(ip)) {
        node.role = "ATTACKER";
      } else if (victimIps.has(ip)) {
        node.role = "VICTIM";
      } else if (ip.endsWith(".1") || ip.endsWith(".254")) {
        node.role = "GATEWAY";
      } else if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) {
        node.role = "CLIENT";
      } else {
        node.role = "SERVER";
      }
    }

    // Build edges from flows
    for (const flow of flows) {
      const srcIp = flow.source.split(":")[0];
      const dstIp = flow.destination.split(":")[0];
      if (!srcIp || !dstIp || srcIp === dstIp) continue;

      const edgeKey = `${srcIp}->${dstIp}:${flow.protocol}`;
      const isMalicious = attackerIps.has(srcIp) || attackerIps.has(dstIp);

      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          id: edgeKey,
          source: srcIp,
          target: dstIp,
          packets: flow.packets_count,
          bytes: flow.bytes_count,
          protocol: flow.protocol,
          isMalicious,
        });
      } else {
        const e = edgeMap.get(edgeKey)!;
        e.packets += flow.packets_count;
        e.bytes += flow.bytes_count;
      }
    }

    // Position nodes gracefully in a 900x520 canvas area
    const nodeList = Array.from(nodeMap.values());
    const width = 860;
    const height = 480;
    const centerX = width / 2;
    const centerY = height / 2;

    // Put Gateway or prominent victim in center, attackers on top/left, clients orbiting
    const gatewayNode = nodeList.find(n => n.role === "GATEWAY");
    const otherNodes = nodeList.filter(n => n !== gatewayNode);

    if (gatewayNode) {
      gatewayNode.x = centerX;
      gatewayNode.y = centerY;
    }

    const radius = Math.min(centerX, centerY) - 80;
    const angleStep = (2 * Math.PI) / Math.max(1, otherNodes.length);

    otherNodes.forEach((node, idx) => {
      const angle = idx * angleStep - Math.PI / 2;
      // Slight oval variation for visual balance
      node.x = centerX + Math.cos(angle) * (radius * 1.15);
      node.y = centerY + Math.sin(angle) * (radius * 0.85);
    });

    return {
      nodes: nodeList,
      edges: Array.from(edgeMap.values()),
    };
  }, [packets, flows, findings, attackerIps, victimIps]);

  // Filtered views
  const filteredEdges = useMemo(() => {
    return edges.filter(e => {
      if (protocolFilter !== "ALL" && e.protocol !== protocolFilter) return false;
      return true;
    });
  }, [edges, protocolFilter]);

  const filteredNodes = useMemo(() => {
    return nodes.filter(n => {
      if (roleFilter !== "ALL") {
        if (roleFilter === "THREATS" && n.role !== "ATTACKER") return false;
        if (roleFilter === "VICTIMS" && n.role !== "VICTIM") return false;
        if (roleFilter === "HEALTHY" && (n.role === "ATTACKER" || n.role === "VICTIM")) return false;
      }
      return true;
    });
  }, [nodes, roleFilter]);

  const selectedNode = useMemo(() => {
    return nodes.find(n => n.id === selectedNodeId) || nodes[0] || null;
  }, [nodes, selectedNodeId]);

  return (
    <div className="space-y-6">
      {/* Control Ribbon */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-raised border border-rule rounded-card">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-ink-2 mr-2">
            <Filter size={14} />
            <span>Protocol:</span>
          </div>
          {["ALL", "TCP", "UDP", "ARP", "DNS"].map(proto => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              className={cn(
                "px-2.5 py-1 rounded-full text-xs font-mono transition-colors",
                protocolFilter === proto
                  ? "bg-brand text-on-brand font-semibold shadow-xs"
                  : "bg-sunk text-ink-2 hover:text-ink hover:bg-raised-hover border border-rule-soft"
              )}
            >
              {proto}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-ink-2 mr-2">
            <span>Filter Hosts:</span>
          </div>
          {[
            { id: "ALL", label: "All Hosts" },
            { id: "THREATS", label: "Threat Actors" },
            { id: "VICTIMS", label: "Target / Affected" },
            { id: "HEALTHY", label: "Benign" },
          ].map(item => (
            <button
              key={item.id}
              onClick={() => setRoleFilter(item.id)}
              className={cn(
                "px-2.5 py-1 rounded-full text-xs transition-colors",
                roleFilter === item.id
                  ? "bg-ink text-canvas font-semibold shadow-xs"
                  : "bg-sunk text-ink-2 hover:text-ink hover:bg-raised-hover border border-rule-soft"
              )}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* Zoom controls */}
        <div className="flex items-center gap-1 bg-sunk p-1 rounded-[10px] border border-rule-soft">
          <button
            onClick={() => setZoomLevel(z => Math.max(0.7, z - 0.15))}
            className="p-1 rounded text-ink-2 hover:text-ink hover:bg-raised transition-colors"
            title="Zoom Out"
          >
            <ZoomOut size={15} />
          </button>
          <span className="text-[11px] font-mono px-1.5 text-ink-2">{Math.round(zoomLevel * 100)}%</span>
          <button
            onClick={() => setZoomLevel(z => Math.min(1.4, z + 0.15))}
            className="p-1 rounded text-ink-2 hover:text-ink hover:bg-raised transition-colors"
            title="Zoom In"
          >
            <ZoomIn size={15} />
          </button>
          <button
            onClick={() => setZoomLevel(1)}
            className="p-1 rounded text-ink-2 hover:text-ink hover:bg-raised transition-colors ml-1"
            title="Reset Zoom"
          >
            <RotateCcw size={13} />
          </button>
        </div>
      </div>

      {/* Main Canvas & Details Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Topology Map Canvas (8 cols) */}
        <div className="lg:col-span-8 bg-canvas border border-rule rounded-card relative overflow-hidden flex flex-col items-center justify-center min-h-[540px] shadow-sm">
          {/* Subtle Grid Background */}
          <div
            className="absolute inset-0 opacity-[0.03] pointer-events-none"
            style={{
              backgroundImage: `radial-gradient(currentColor 1px, transparent 1px)`,
              backgroundSize: "24px 24px",
            }}
          />

          {/* SVG Graph */}
          <div className="w-full h-full flex items-center justify-center p-4 overflow-auto">
            <svg
              viewBox="0 0 860 480"
              className="w-full max-w-[860px] h-auto transition-transform duration-200"
              style={{ transform: `scale(${zoomLevel})` }}
            >
              <defs>
                {/* Arrow markers for edges */}
                <marker
                  id="arrow-normal"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#71717a" opacity="0.6" />
                </marker>
                <marker
                  id="arrow-attack"
                  viewBox="0 0 10 10"
                  refX="18"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" fill="#dc2626" />
                </marker>
              </defs>

              {/* Communication Edges */}
              {filteredEdges.map(edge => {
                const srcNode = nodes.find(n => n.id === edge.source);
                const dstNode = nodes.find(n => n.id === edge.target);
                if (!srcNode || !dstNode) return null;

                const isAttack = edge.isMalicious;

                return (
                  <g key={edge.id} className="transition-opacity duration-300">
                    <line
                      x1={srcNode.x}
                      y1={srcNode.y}
                      x2={dstNode.x}
                      y2={dstNode.y}
                      stroke={isAttack ? "#dc2626" : "#71717a"}
                      strokeWidth={isAttack ? 2.5 : Math.max(1, Math.min(3, Math.log10(edge.packets) * 1.2))}
                      strokeDasharray={isAttack ? "6,4" : "none"}
                      strokeOpacity={isAttack ? 0.9 : 0.4}
                      markerEnd={isAttack ? "url(#arrow-attack)" : "url(#arrow-normal)"}
                    />
                    {/* Animated moving pulse for active streams */}
                    {isAttack && (
                      <circle r="3" fill="#dc2626">
                        <animateMotion
                          path={`M ${srcNode.x} ${srcNode.y} L ${dstNode.x} ${dstNode.y}`}
                          dur="1.5s"
                          repeatCount="indefinite"
                        />
                      </circle>
                    )}
                  </g>
                );
              })}

              {/* Host Nodes */}
              {filteredNodes.map(node => {
                const isSelected = selectedNodeId === node.id;
                const isAttacker = node.role === "ATTACKER";
                const isVictim = node.role === "VICTIM";
                const isGateway = node.role === "GATEWAY";

                // Node coloring
                let fillColor = "#ffffff";
                let strokeColor = "#a1a1aa";
                let pulseColor = "#ef4444";

                if (isAttacker) {
                  fillColor = "#fef2f2";
                  strokeColor = "#dc2626";
                } else if (isVictim) {
                  fillColor = "#fffbeb";
                  strokeColor = "#d97706";
                } else if (isGateway) {
                  fillColor = "#f0fdf4";
                  strokeColor = "#16a34a";
                }

                return (
                  <g
                    key={node.id}
                    className="cursor-pointer group"
                    onClick={() => setSelectedNodeId(node.id)}
                  >
                    {/* Pulsing ring for attacker or victim */}
                    {isAttacker && (
                      <circle
                        cx={node.x}
                        cy={node.y}
                        r="32"
                        fill="none"
                        stroke="#dc2626"
                        strokeWidth="1.5"
                        opacity="0.4"
                      >
                        <animate
                          attributeName="r"
                          values="26;42;26"
                          dur="2s"
                          repeatCount="indefinite"
                        />
                        <animate
                          attributeName="opacity"
                          values="0.6;0;0.6"
                          dur="2s"
                          repeatCount="indefinite"
                        />
                      </circle>
                    )}

                    {/* Main Node Circle */}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={isSelected ? 24 : 20}
                      fill={fillColor}
                      stroke={isSelected ? "#2563eb" : strokeColor}
                      strokeWidth={isSelected ? 3 : 2}
                      className="transition-all duration-200 drop-shadow-sm group-hover:filter group-hover:brightness-95"
                    />

                    {/* Node Role Icon */}
                    <g transform={`translate(${node.x - 7}, ${node.y - 7})`}>
                      {isAttacker ? (
                        <Flame size={14} className="text-red-600" />
                      ) : isVictim ? (
                        <AlertTriangle size={14} className="text-amber-600" />
                      ) : isGateway ? (
                        <Wifi size={14} className="text-green-600" />
                      ) : node.role === "SERVER" ? (
                        <Server size={14} className="text-blue-600" />
                      ) : (
                        <Laptop size={14} className="text-zinc-600" />
                      )}
                    </g>

                    {/* Node IP Text */}
                    <text
                      x={node.x}
                      y={node.y + 34}
                      textAnchor="middle"
                      className={cn(
                        "text-[11px] font-mono font-medium fill-current transition-colors",
                        isSelected ? "fill-brand font-bold" : "fill-ink"
                      )}
                    >
                      {node.ip}
                    </text>

                    {/* Role Tag */}
                    <text
                      x={node.x}
                      y={node.y + 46}
                      textAnchor="middle"
                      className={cn(
                        "text-[9px] font-sans uppercase font-bold tracking-wider",
                        isAttacker
                          ? "fill-red-600"
                          : isVictim
                          ? "fill-amber-600"
                          : isGateway
                          ? "fill-green-600"
                          : "fill-ink-2"
                      )}
                    >
                      {node.role}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Interactive Legend in Footer */}
          <div className="w-full border-t border-rule bg-raised/90 p-3 px-6 flex flex-wrap items-center justify-between text-xs text-ink-2">
            <div className="flex flex-wrap items-center gap-4">
              <span className="flex items-center gap-1.5 font-medium text-ink">
                <span className="w-2.5 h-2.5 rounded-full bg-red-600 ring-2 ring-red-200 animate-pulse" />
                Attacker / Threat Node
              </span>
              <span className="flex items-center gap-1.5 font-medium text-ink">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                Target / Impacted Node
              </span>
              <span className="flex items-center gap-1.5 font-medium text-ink">
                <span className="w-2.5 h-2.5 rounded-full bg-green-600" />
                Gateway / Infrastructure
              </span>
              <span className="flex items-center gap-1.5 text-ink-2">
                <span className="w-4 h-0.5 border-b-2 border-dashed border-red-500 inline-block" />
                Hostile Flow
              </span>
            </div>
            <div className="text-[11px] font-mono">
              Click any node to inspect telemetry
            </div>
          </div>
        </div>

        {/* Selected Node Inspector Drawer (4 cols) */}
        <div className="lg:col-span-4 bg-raised border border-rule rounded-card p-6 flex flex-col justify-between shadow-sm space-y-6">
          {selectedNode ? (
            <div className="space-y-6">
              {/* Node Header */}
              <div className="border-b border-rule pb-4">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono uppercase text-ink-2 tracking-wider">
                    Host Inspection
                  </span>
                  <Chip
                    tone={
                      selectedNode.role === "ATTACKER"
                        ? "flag"
                        : selectedNode.role === "VICTIM"
                        ? "warn"
                        : "muted"
                    }
                  >
                    {selectedNode.role}
                  </Chip>
                </div>
                <h3 className="text-xl font-bold font-mono text-ink mt-1">
                  {selectedNode.ip}
                </h3>
                {selectedNode.mac && (
                  <p className="text-xs font-mono text-ink-2 mt-0.5">
                    MAC: {selectedNode.mac}
                  </p>
                )}
              </div>

              {/* Node Telemetry Numbers */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-sunk p-3 rounded-[10px] border border-rule-soft">
                  <div className="text-[10px] uppercase font-bold text-ink-2">Packets Sent</div>
                  <div className="text-base font-bold font-mono text-ink mt-0.5">
                    {selectedNode.packetsOut.toLocaleString()}
                  </div>
                </div>
                <div className="bg-sunk p-3 rounded-[10px] border border-rule-soft">
                  <div className="text-[10px] uppercase font-bold text-ink-2">Packets Received</div>
                  <div className="text-base font-bold font-mono text-ink mt-0.5">
                    {selectedNode.packetsIn.toLocaleString()}
                  </div>
                </div>
                <div className="bg-sunk p-3 rounded-[10px] border border-rule-soft">
                  <div className="text-[10px] uppercase font-bold text-ink-2">Total Volume</div>
                  <div className="text-base font-bold font-mono text-ink mt-0.5">
                    {formatBytes(selectedNode.bytesTotal)}
                  </div>
                </div>
                <div className="bg-sunk p-3 rounded-[10px] border border-rule-soft">
                  <div className="text-[10px] uppercase font-bold text-ink-2">Protocols</div>
                  <div className="text-xs font-mono text-ink mt-1 flex flex-wrap gap-1">
                    {Array.from(selectedNode.protocols).map(p => (
                      <span key={p} className="bg-raised px-1.5 py-0.5 rounded text-[10px] border border-rule-soft">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Correlated Security & Fault Findings */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-ink flex items-center gap-1.5">
                    <ShieldAlert size={14} className="text-brand" />
                    Correlated Findings ({selectedNode.associatedFindings.length})
                  </span>
                </div>

                {selectedNode.associatedFindings.length > 0 ? (
                  <div className="space-y-2 max-h-[180px] overflow-y-auto pr-1">
                    {selectedNode.associatedFindings.map(f => (
                      <Link
                        key={f.id}
                        href={`/findings/${f.id}`}
                        className="block p-2.5 bg-sunk hover:bg-raised-hover border border-rule-soft rounded-[10px] transition-colors"
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-mono font-bold text-ink">{f.id}</span>
                          <Chip tone={f.severity === "CRITICAL" ? "flag" : f.severity === "HIGH" ? "warn" : "muted"}>
                            {f.severity}
                          </Chip>
                        </div>
                        <div className="text-xs font-semibold text-ink line-clamp-1 mt-1">
                          {f.issue_title}
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-sunk/60 rounded-[10px] border border-rule-soft text-xs text-ink-2 flex items-center gap-2">
                    <CheckCircle2 size={15} className="text-green-600 shrink-0" />
                    <span>No active security incidents or operational faults tied directly to this host.</span>
                  </div>
                )}
              </div>

              {/* Direct Deep-Links */}
              <div className="pt-2 border-t border-rule space-y-2">
                <Link
                  href={`/packets`}
                  className="w-full flex items-center justify-center gap-2 h-9 rounded-[10px] bg-brand text-on-brand font-semibold text-xs hover:bg-brand-deep transition-colors"
                >
                  <Activity size={13} />
                  <span>Inspect Packets for {selectedNode.ip}</span>
                </Link>
                <Link
                  href={`/flows`}
                  className="w-full flex items-center justify-center gap-2 h-9 rounded-[10px] bg-sunk hover:bg-raised-hover text-ink font-semibold text-xs border border-rule transition-colors"
                >
                  <Layers size={13} />
                  <span>View Host Conversations in Flows</span>
                </Link>
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-ink-2 text-sm">
              Select a node on the canvas to inspect technical host telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
