"use client";

import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Copy,
  ArrowRight,
  Activity,
} from "lucide-react";
import { Button, Chip, Panel, Swatch, cn } from "./ui";
import { DiagnosticSummary } from "@/lib/engine/types";

interface SummaryHeroProps {
  summary: DiagnosticSummary;
  onCopyJson: () => void;
  onScrollToFindings: () => void;
}

export function SummaryHero({
  summary,
  onCopyJson,
  onScrollToFindings,
}: SummaryHeroProps) {
  const isCritical = summary.overall_health_status === "CRITICAL";
  const isWarning = summary.overall_health_status === "WARNING";
  const isHealthy = summary.overall_health_status === "HEALTHY";

  const getStatusTone = () => {
    if (isCritical) return "flag";
    if (isWarning) return "warn";
    return "ok";
  };

  const getClassificationMeta = () => {
    switch (summary.primary_classification) {
      case "MALICIOUS_ATTACK":
        return {
          label: "Malicious Attack",
          tone: "flag" as const,
          swatchColor: "var(--color-c-exploit)",
          desc: "Targeted malicious activity with high confidence",
        };
      case "BENIGN_FAULT":
        return {
          label: "Benign Operational Fault",
          tone: "warn" as const,
          swatchColor: "var(--color-c-latency)",
          desc: "Infrastructure or protocol misconfiguration (Non-malicious)",
        };
      case "MIXED":
        return {
          label: "Mixed: Attack + Operational Fault",
          tone: "pend" as const,
          swatchColor: "var(--color-c-routing)",
          desc: "Concurrent operational outages and active cyber threats",
        };
      case "NO_ISSUE":
      default:
        return {
          label: "Clean Nominal Traffic",
          tone: "ok" as const,
          swatchColor: "var(--color-c-healthy)",
          desc: "Network is operating within nominal parameters",
        };
    }
  };

  const meta = getClassificationMeta();

  return (
    <Panel
      className={cn(
        "p-6 relative overflow-hidden transition-all",
        isCritical
          ? "border-l-[5px] border-l-flag shadow-sm"
          : isWarning
          ? "border-l-[5px] border-l-warn shadow-sm"
          : "border-l-[5px] border-l-ok"
      )}
    >
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        <div className="space-y-3.5 max-w-3xl">
          {/* Status Badges Row */}
          <div className="flex flex-wrap items-center gap-2">
            <Chip tone={getStatusTone()}>
              {isCritical ? (
                <>
                  <Flame size={13} className="text-flag" /> Critical Status
                </>
              ) : isWarning ? (
                <>
                  <AlertTriangle size={13} className="text-warn" /> Warning Status
                </>
              ) : (
                <>
                  <CheckCircle2 size={13} className="text-ok" /> Healthy Network
                </>
              )}
            </Chip>

            <Chip tone={meta.tone}>
              <Swatch color={meta.swatchColor} />
              {meta.label}
            </Chip>

            <span className="text-xs text-ink-3 pl-1 font-mono">
              {summary.total_packets_analyzed} packets analyzed
            </span>
          </div>

          {/* Headline & Grounded Plain-Language Summary */}
          <div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-[-0.022em] text-ink mb-1.5">
              Diagnostic Verdict
            </h1>
            <p className="text-[1.02rem] text-ink-2 leading-[1.6] max-w-2xl font-normal">
              {summary.executive_summary}
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-row lg:flex-col gap-2.5 shrink-0 w-full sm:w-auto">
          <Button
            variant="primary"
            size="md"
            onClick={onScrollToFindings}
            className="flex-1 sm:flex-initial"
          >
            <span>Inspect Remediation</span>
            <ArrowRight size={15} />
          </Button>
          <Button
            variant="secondary"
            size="md"
            onClick={onCopyJson}
            className="flex-1 sm:flex-initial"
          >
            <Copy size={14} className="text-ink-2" />
            <span>Copy Diagnostic JSON</span>
          </Button>
        </div>
      </div>
    </Panel>
  );
}
