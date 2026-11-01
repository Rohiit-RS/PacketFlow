"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Search,
  Zap,
  ShieldAlert,
  Wrench,
  AlertTriangle,
  ArrowRight,
  Clock,
  Layers,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { Chip, Panel, SectionTitle, Swatch, cn } from "./ui";
import { IncidentTimelineEvent } from "@/lib/engine/types";

interface IncidentTimelineProps {
  timeline?: IncidentTimelineEvent[];
}

export function IncidentTimeline({ timeline }: IncidentTimelineProps) {
  const [isExpanded, setIsExpanded] = useState(true);

  if (!timeline || timeline.length === 0) {
    return null;
  }

  const getPhaseMeta = (phase: string) => {
    switch (phase) {
      case "RECONNAISSANCE":
        return {
          label: "Phase 1: Reconnaissance",
          tone: "brand" as const,
          icon: Search,
          bg: "bg-blue-500/10 border-blue-500/30 text-blue-600 dark:text-blue-400",
        };
      case "EXPLOITATION":
        return {
          label: "Phase 2: Incursion / Exploit",
          tone: "flag" as const,
          icon: ShieldAlert,
          bg: "bg-red-500/10 border-red-500/30 text-flag",
        };
      case "COLLATERAL_FAULT":
        return {
          label: "Phase 3: Induced Operational Symptom",
          tone: "warn" as const,
          icon: Zap,
          bg: "bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400",
        };
      case "IMPACT":
      default:
        return {
          label: "Operational Impact",
          tone: "muted" as const,
          icon: AlertTriangle,
          bg: "bg-zinc-500/10 border-zinc-500/30 text-ink-2",
        };
    }
  };

  return (
    <Panel className="p-6 sm:p-8 border border-rule shadow-xs space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-rule">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Layers size={18} className="text-brand" />
            <span className="text-xs font-bold uppercase tracking-wider text-ink-3">
              Cross-Layer Diagnostic Correlation
            </span>
          </div>
          <h3 className="text-xl sm:text-2xl font-bold text-ink tracking-tight">
            Incident Kill-Chain Timeline
          </h3>
          <p className="text-sm text-ink-2 mt-1">
            Chronological reconstruction establishing how initial probes led to security exploits and downstream network outages.
          </p>
        </div>

        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-xs text-ink-3 hover:text-ink font-semibold inline-flex items-center gap-1.5 self-end sm:self-auto cursor-pointer"
        >
          <span>{isExpanded ? "Collapse Timeline" : "Expand Timeline"}</span>
          {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {isExpanded && (
        <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-rule">
          {timeline.map((evt, idx) => {
            const meta = getPhaseMeta(evt.phase);
            const Icon = meta.icon;

            return (
              <div key={idx} className="relative group">
                {/* Node Dot */}
                <div className="absolute -left-6 sm:-left-8 top-1.5 w-6 h-6 rounded-full bg-raised border-2 border-rule flex items-center justify-center group-hover:border-brand transition-colors">
                  <div className="w-2 h-2 rounded-full bg-brand" />
                </div>

                {/* Event Card */}
                <div className="p-5 rounded-2xl bg-sunk/60 border border-rule hover:border-brand/40 transition-all space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={cn("px-2.5 py-0.5 rounded-full text-xs font-bold font-mono border", meta.bg)}>
                        Step {evt.step} &bull; {meta.label}
                      </span>
                      {evt.finding_id && (
                        <Link
                          href={`/findings/${evt.finding_id}`}
                          className="font-mono text-xs font-bold px-2 py-0.5 rounded-md bg-raised text-brand border border-rule hover:underline"
                        >
                          {evt.finding_id}
                        </Link>
                      )}
                    </div>

                    <div className="flex items-center gap-2 text-xs font-mono text-ink-3">
                      <Clock size={12} />
                      <span>T+{evt.timestamp.toFixed(2)}s</span>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-base font-bold text-ink">
                      {evt.title}
                    </h4>
                    <p className="text-sm text-ink-2 mt-1 leading-relaxed font-normal">
                      {evt.detail}
                    </p>
                  </div>

                  {(evt.actor_ip || evt.target_ip) && (
                    <div className="flex flex-wrap items-center gap-2 pt-1 text-xs font-mono text-ink-2">
                      {evt.actor_ip && (
                        <span className="px-2 py-0.5 rounded bg-raised border border-rule">
                          Actor: <strong className="text-ink">{evt.actor_ip}</strong>
                        </span>
                      )}
                      {evt.target_ip && (
                        <span className="px-2 py-0.5 rounded bg-raised border border-rule">
                          Target: <strong className="text-ink">{evt.target_ip}</strong>
                        </span>
                      )}
                      {evt.finding_id && (
                        <Link
                          href={`/findings/${evt.finding_id}`}
                          className="text-xs text-brand hover:underline font-sans font-semibold inline-flex items-center gap-1 ml-auto"
                        >
                          <span>Inspect Finding</span>
                          <ArrowRight size={12} />
                        </Link>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Panel>
  );
}
