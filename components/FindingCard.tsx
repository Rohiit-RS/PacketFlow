"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Wrench,
  Info,
  ChevronDown,
  ChevronUp,
  Terminal,
  Zap,
  ShieldCheck,
  ArrowRight,
} from "lucide-react";
import { Chip, Panel, Swatch, cn } from "./ui";
import { Finding } from "@/lib/engine/types";

interface FindingCardProps {
  finding: Finding;
  onSelectEvidence?: (packetSummary: string) => void;
}

export function FindingCard({ finding, onSelectEvidence }: FindingCardProps) {
  const [expanded, setExpanded] = useState(true);

  const isAttack = finding.category === "ATTACK";
  const isCritical = finding.severity === "CRITICAL";

  const getSeverityTone = () => {
    switch (finding.severity) {
      case "CRITICAL":
        return "flag";
      case "HIGH":
        return "warn";
      case "MEDIUM":
        return "pend";
      case "LOW":
      default:
        return "muted";
    }
  };

  return (
    <Panel
      className={cn(
        "p-6 sm:p-8 transition-all border shadow-xs",
        isAttack && isCritical ? "border-l-[6px] border-l-flag border-rule" : "border-rule hover:border-brand/40"
      )}
    >
      {/* Top Header Line */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-rule">
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Finding ID */}
          <Link
            href={`/findings/${finding.id}`}
            className="font-mono text-sm font-bold px-3 py-1 rounded-lg bg-sunk text-ink border border-rule hover:text-brand hover:border-brand transition-colors"
          >
            {finding.id}
          </Link>

          {/* Category Chip */}
          <Chip tone={isAttack ? "flag" : "warn"}>
            <Swatch
              color={isAttack ? "var(--color-flag)" : "var(--color-warn)"}
              className="w-2.5 h-2.5 rounded-full"
            />
            {isAttack ? "Malicious Attack" : "Operational Fault"}
          </Chip>

          {/* Severity Chip */}
          <Chip tone={getSeverityTone()}>
            {finding.severity}
          </Chip>

          {/* Confidence Score */}
          <div className="inline-flex items-center gap-1.5 rounded-full border border-rule bg-sunk px-3 py-1 text-xs text-ink-2 font-mono font-medium">
            <span>Confidence:</span>
            <span
              className={cn(
                "font-bold",
                finding.confidence_score >= 90
                  ? "text-ok"
                  : finding.confidence_score >= 75
                  ? "text-warn"
                  : "text-ink-2"
              )}
            >
              {finding.confidence_score}%
            </span>
          </div>

          {finding.mitre_technique && (
            <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-red-500/10 text-red-600 border border-red-500/20 font-bold">
              MITRE {finding.mitre_technique.id}
            </span>
          )}
        </div>

        <div className="flex items-center gap-4 self-end sm:self-auto">
          <Link
            href={`/findings/${finding.id}`}
            className="text-sm font-semibold text-brand hover:underline inline-flex items-center gap-1.5"
          >
            <span>Dossier View</span>
            <ArrowRight size={14} />
          </Link>

          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-ink-3 hover:text-ink font-semibold inline-flex items-center gap-1 cursor-pointer"
          >
            <span>{expanded ? "Collapse" : "Expand"}</span>
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Main Body */}
      <div className="pt-4 space-y-4">
        <Link href={`/findings/${finding.id}`} className="block group">
          <h3 className="text-xl sm:text-2xl font-bold text-ink group-hover:text-brand transition-colors tracking-tight">
            {finding.issue_title}
          </h3>
        </Link>

        {/* Beginner-friendly plain-language explanation */}
        <div className="p-5 rounded-xl bg-sunk/60 border border-rule-soft">
          <div className="flex items-start gap-3">
            <Info size={18} className="text-brand shrink-0 mt-0.5" />
            <div>
              <span className="text-xs font-bold text-ink uppercase tracking-wider block mb-1">
                Plain-Language Explanation (Non-Expert Guide)
              </span>
              <p className="text-base text-ink-2 leading-relaxed font-normal">
                {finding.plain_language_explanation}
              </p>
            </div>
          </div>
        </div>

        {expanded && (
          <div className="space-y-5 animate-in fade-in pt-1">
            {/* Technical Root Cause */}
            <div>
              <span className="text-xs font-bold text-ink-3 uppercase tracking-wider block mb-1.5">
                Technical Root Cause &amp; Telemetry Breakdown
              </span>
              <p className="text-sm text-ink-2 leading-relaxed p-4 rounded-xl bg-raised border border-rule font-sans">
                {finding.technical_details.root_cause}
              </p>
            </div>

            {/* Cited Evidence Packets */}
            <div>
              <span className="text-xs font-bold text-ink-3 uppercase tracking-wider block mb-2">
                Cited Evidence Packets ({finding.technical_details.evidence_packets.length})
              </span>
              <div className="space-y-2">
                {finding.technical_details.evidence_packets.map((ev, idx) => {
                  const frameMatch = ev.match(/Frame #(\d+)/);
                  const frameNum = frameMatch ? frameMatch[1] : null;

                  return (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-sunk/50 border border-rule font-mono text-xs text-ink flex items-center justify-between hover:border-rule-strong hover:bg-sunk transition-colors"
                    >
                      <div className="flex items-center gap-2.5 truncate">
                        <Swatch color="var(--color-brand)" className="w-2 h-2 rounded-full" />
                        <span className="truncate">{ev}</span>
                      </div>
                      {frameNum ? (
                        <Link
                          href={`/packets?frame=${frameNum}`}
                          className="text-xs text-brand font-semibold shrink-0 ml-2 hover:underline inline-flex items-center gap-1"
                        >
                          <span>Frame #{frameNum}</span>
                          <ArrowRight size={12} />
                        </Link>
                      ) : (
                        <span className="text-xs text-ink-3 font-sans">Log Trace</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Symmetric Dual Action Remediation Boxes */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-stretch pt-2">
              {/* Immediate Action (Equal Height) */}
              <div className="p-5 rounded-xl border border-flag-line/40 bg-flag-soft/20 flex flex-col justify-start h-full">
                <div className="flex items-center gap-2 mb-2">
                  <Zap size={16} className="text-flag" />
                  <span className="text-xs font-bold text-flag uppercase tracking-wide">
                    Immediate Action (Contain Outage / Attack)
                  </span>
                </div>
                <p className="text-sm text-ink leading-relaxed font-medium">
                  {finding.recommended_remediation.immediate_action}
                </p>
              </div>

              {/* Long-Term Fix (Equal Height) */}
              <div className="p-5 rounded-xl border border-ok-line/40 bg-ok-soft/20 flex flex-col justify-start h-full">
                <div className="flex items-center gap-2 mb-2">
                  <ShieldCheck size={16} className="text-ok" />
                  <span className="text-xs font-bold text-ok uppercase tracking-wide">
                    Long-Term Fix (Prevent Recurrence)
                  </span>
                </div>
                <p className="text-sm text-ink leading-relaxed font-medium">
                  {finding.recommended_remediation.long_term_fix}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}
