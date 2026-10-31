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
          label: "Targeted Malicious Attack",
          tone: "flag" as const,
          swatchColor: "var(--color-c-exploit)",
        };
      case "BENIGN_FAULT":
        return {
          label: "Benign Operational Fault",
          tone: "warn" as const,
          swatchColor: "var(--color-c-latency)",
        };
      case "MIXED":
        return {
          label: "Mixed: Outage + Cyber Threat",
          tone: "pend" as const,
          swatchColor: "var(--color-c-routing)",
        };
      case "NO_ISSUE":
      default:
        return {
          label: "Nominal Network Traffic",
          tone: "ok" as const,
          swatchColor: "var(--color-c-healthy)",
        };
    }
  };

  const meta = getClassificationMeta();

  return (
    <Panel
      className={cn(
        "p-8 lg:p-10 relative overflow-hidden transition-all shadow-sm border",
        isCritical
          ? "border-l-[6px] border-l-flag border-rule"
          : isWarning
          ? "border-l-[6px] border-l-warn border-rule"
          : "border-l-[6px] border-l-ok border-rule"
      )}
    >
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-8">
        <div className="space-y-4 max-w-4xl">
          {/* Status Badges Row */}
          <div className="flex flex-wrap items-center gap-3">
            <Chip tone={getStatusTone()}>
              {isCritical ? (
                <>
                  <Flame size={15} className="text-flag" /> Critical Status
                </>
              ) : isWarning ? (
                <>
                  <AlertTriangle size={15} className="text-warn" /> Warning Status
                </>
              ) : (
                <>
                  <CheckCircle2 size={15} className="text-ok" /> Healthy Network
                </>
              )}
            </Chip>

            <Chip tone={meta.tone}>
              <Swatch color={meta.swatchColor} className="w-2.5 h-2.5 rounded-full" />
              {meta.label}
            </Chip>

            <span className="text-sm text-ink-3 pl-1 font-mono font-medium">
              {summary.total_packets_analyzed.toLocaleString()} frames analyzed
            </span>
          </div>

          {/* Headline & Grounded Plain-Language Summary */}
          <div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-[-0.025em] text-ink mb-2">
              Diagnostic Health Verdict
            </h1>
            <p className="text-base sm:text-lg text-ink-2 leading-relaxed font-normal">
              {summary.executive_summary}
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-col sm:flex-row lg:flex-col gap-3 shrink-0 w-full lg:w-auto">
          <Button
            variant="primary"
            size="md"
            onClick={onScrollToFindings}
            className="w-full sm:w-auto justify-center"
          >
            <span>Review Findings</span>
            <ArrowRight size={16} />
          </Button>
          <Button
            variant="secondary"
            size="md"
            onClick={onCopyJson}
            className="w-full sm:w-auto justify-center"
          >
            <Copy size={15} className="text-ink-2" />
            <span>Copy Diagnostic JSON</span>
          </Button>
        </div>
      </div>
    </Panel>
  );
}
