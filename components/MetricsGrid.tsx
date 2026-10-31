"use client";

import {
  Layers,
  Wrench,
  ShieldAlert,
  Clock,
  ArrowDownUp,
  Percent,
} from "lucide-react";
import { Panel, Swatch, cn } from "./ui";
import { formatBytes } from "@/lib/utils/formatters";

interface MetricsGridProps {
  stats: {
    total_packets: number;
    total_bytes: number;
    fault_count: number;
    attack_count: number;
    critical_count: number;
    average_rtt_ms: number;
    packet_loss_percentage: number;
  };
  flowsCount: number;
}

export function MetricsGrid({ stats, flowsCount }: MetricsGridProps) {
  const cards = [
    {
      label: "Packets Analyzed",
      value: stats.total_packets.toLocaleString(),
      sub: formatBytes(stats.total_bytes),
      swatchColor: "var(--color-brand)",
      icon: Layers,
    },
    {
      label: "Active Flows",
      value: String(flowsCount),
      sub: "Bidirectional streams",
      swatchColor: "var(--color-c-tcp)",
      icon: ArrowDownUp,
    },
    {
      label: "Operational Faults",
      value: String(stats.fault_count),
      sub: stats.fault_count > 0 ? "TCP / DNS / MTU outages" : "Zero outages",
      swatchColor: stats.fault_count > 0 ? "var(--color-warn)" : "var(--color-ok)",
      icon: Wrench,
    },
    {
      label: "Security Incidents",
      value: String(stats.attack_count),
      sub: stats.attack_count > 0 ? `${stats.critical_count} critical threat(s)` : "Zero threats",
      swatchColor: stats.attack_count > 0 ? "var(--color-flag)" : "var(--color-ok)",
      icon: ShieldAlert,
    },
    {
      label: "Avg RTT Latency",
      value: `${stats.average_rtt_ms} ms`,
      sub: stats.average_rtt_ms > 200 ? "High round-trip delay" : "Nominal delay",
      swatchColor: stats.average_rtt_ms > 200 ? "var(--color-warn)" : "var(--color-c-tcp)",
      icon: Clock,
    },
    {
      label: "Packet Loss Rate",
      value: `${stats.packet_loss_percentage}%`,
      sub: stats.packet_loss_percentage > 5 ? "Elevated drop rate" : "Zero packet loss",
      swatchColor: stats.packet_loss_percentage > 5 ? "var(--color-flag)" : "var(--color-ok)",
      icon: Percent,
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <Panel key={idx} className="p-3.5 flex flex-col justify-between hover:border-rule-strong transition-colors">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-ink-3">
                {card.label}
              </span>
              <Swatch color={card.swatchColor} />
            </div>
            <div>
              <p className="text-xl font-bold tracking-tight text-ink font-sans">
                {card.value}
              </p>
              <p className="text-xs text-ink-2 mt-0.5 truncate">
                {card.sub}
              </p>
            </div>
          </Panel>
        );
      })}
    </div>
  );
}
