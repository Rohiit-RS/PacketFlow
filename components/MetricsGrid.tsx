"use client";

import {
  Layers,
  Wrench,
  ShieldAlert,
  Activity,
  CheckCircle2,
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
      label: "Analyzed Telemetry",
      value: `${stats.total_packets.toLocaleString()} frames`,
      sub: `${formatBytes(stats.total_bytes)} • ${flowsCount} active flows`,
      swatchColor: "var(--color-brand)",
      icon: Layers,
    },
    {
      label: "Operational Outages",
      value: `${stats.fault_count} ${stats.fault_count === 1 ? "Fault" : "Faults"}`,
      sub: stats.fault_count > 0 ? "TCP / DNS / MTU degradation" : "Zero infrastructure faults",
      swatchColor: stats.fault_count > 0 ? "var(--color-warn)" : "var(--color-ok)",
      icon: Wrench,
    },
    {
      label: "Cyber Threat Events",
      value: `${stats.attack_count} ${stats.attack_count === 1 ? "Attack" : "Attacks"}`,
      sub: stats.attack_count > 0 ? `${stats.critical_count} critical threat(s)` : "Zero malicious activities",
      swatchColor: stats.attack_count > 0 ? "var(--color-flag)" : "var(--color-ok)",
      icon: ShieldAlert,
    },
    {
      label: "Latency & Loss Rate",
      value: `${stats.packet_loss_percentage}% Loss`,
      sub: `Average RTT: ${stats.average_rtt_ms} ms`,
      swatchColor: stats.packet_loss_percentage > 3 ? "var(--color-flag)" : "var(--color-ok)",
      icon: Activity,
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 items-stretch">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <Panel
            key={idx}
            className="p-6 flex flex-col justify-between h-full border border-rule hover:border-brand/40 transition-colors shadow-xs"
          >
            <div className="flex items-center justify-between mb-4">
              <span className="text-sm uppercase tracking-wider font-bold text-ink-3">
                {card.label}
              </span>
              <Swatch color={card.swatchColor} className="w-3.5 h-3.5 rounded" />
            </div>

            <div>
              <p className="text-3xl font-extrabold tracking-tight text-ink font-sans">
                {card.value}
              </p>
              <p className="text-sm font-medium text-ink-2 mt-2">
                {card.sub}
              </p>
            </div>
          </Panel>
        );
      })}
    </div>
  );
}
