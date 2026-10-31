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
        "p-5 transition-all border",
        isAttack && isCritical ? "border-flag-line hover:border-flag" : "border-rule hover:border-rule-strong"
      )}
    >
      {/* Top Header Line */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-rule-soft">
        <div className="flex flex-wrap items-center gap-2">
          {/* Finding ID */}
          <Link
            href={`/findings/${finding.id}`}
            className="font-mono text-xs font-semibold px-2 py-0.5 rounded-[6px] bg-sunk text-ink-2 border border-rule hover:text-brand hover:border-brand transition-colors"
          >
            {finding.id}
          </Link>

          {/* Category Chip */}
          <Chip tone={isAttack ? "flag" : "warn"}>
            <Swatch
              color={isAttack ? "var(--color-flag)" : "var(--color-warn)"}
            />
            {isAttack ? "Cyber Attack" : "Operational Fault"}
          </Chip>

          {/* Severity Chip */}
          <Chip tone={getSeverityTone()}>
            {finding.severity}
          </Chip>

          {/* Confidence Score */}
          <div className="inline-flex items-center gap-1.5 rounded-full border border-rule bg-sunk px-2.5 py-0.5 text-xs text-ink-2 font-mono">
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
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-600 border border-red-500/20 font-bold">
              MITRE {finding.mitre_technique.id}
            </span>
          )}
        </div>

        <div className="flex items-center gap-3 self-end sm:self-auto">
          <Link
            href={`/findings/${finding.id}`}
            className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1"
          >
            <span>Dossier Page</span>
            <ArrowRight size={12} />
          </Link>

          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="text-xs text-ink-3 hover:text-ink font-semibold inline-flex items-center gap-1 cursor-pointer"
          >
            <span>{expanded ? "Collapse" : "Expand"}</span>
            {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          </button>
        </div>
      </div>

      {/* Main Body */}
      <div className="pt-3.5 space-y-3.5">
        <Link href={`/findings/${finding.id}`} className="block group">
          <h3 className="text-[1.125rem] font-bold text-ink group-hover:text-brand transition-colors tracking-tight">
            {finding.issue_title}
          </h3>
        </Link>

        {/* Beginner-friendly plain-language explanation */}
        <div className="p-3.5 rounded-[12px] bg-sunk/60 border border-rule-soft">
          <div className="flex items-start gap-2.5">
            <Info size={16} className="text-brand shrink-0 mt-0.5" />
            <div>
              <span className="text-xs font-bold text-ink uppercase tracking-wide block mb-1">
                Plain-Language Explanation (Non-Expert Summary)
              </span>
              <p className="text-[0.9375rem] text-ink-2 leading-[1.55]">
                {finding.plain_language_explanation}
              </p>
            </div>
          </div>
        </div>

        {expanded && (
          <div className="space-y-4 animate-in fade-in pt-1">
            {/* Technical Root Cause */}
            <div>
              <span className="text-xs font-semibold text-ink-3 uppercase tracking-wider block mb-1">
                Technical Root Cause &amp; Telemetry Breakdown
              </span>
              <p className="text-[0.9375rem] text-ink-2 leading-[1.55] p-3 rounded-[10px] bg-raised border border-rule">
                {finding.technical_details.root_cause}
              </p>
            </div>

            {/* Cited Evidence Packets */}
            <div>
              <span className="text-xs font-semibold text-ink-3 uppercase tracking-wider block mb-1.5">
                Cited Evidence Packets ({finding.technical_details.evidence_packets.length})
              </span>
              <div className="space-y-1.5">
                {finding.technical_details.evidence_packets.map((ev, idx) => {
                  const frameMatch = ev.match(/Frame #(\d+)/);
                  const frameNum = frameMatch ? frameMatch[1] : null;

                  return (
                    <div
                      key={idx}
                      className="p-2.5 rounded-[10px] bg-sunk/50 border border-rule font-mono text-xs text-ink flex items-center justify-between hover:border-rule-strong hover:bg-sunk transition-colors"
                    >
                      <div className="flex items-center gap-2 truncate">
                        <Swatch color="var(--color-brand)" />
                        <span className="truncate">{ev}</span>
                      </div>
                      {frameNum ? (
                        <Link
                          href={`/packets?frame=${frameNum}`}
                          className="text-[11px] text-brand font-semibold shrink-0 ml-2 hover:underline inline-flex items-center gap-1"
                        >
                          <span>Frame #{frameNum}</span>
                          <ArrowRight size={11} />
                        </Link>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Dual Action Remediation */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
              {/* Immediate Action */}
              <div className="p-3.5 rounded-[12px] border border-flag-line/40 bg-flag-soft/20">
                <div className="flex items-center gap-2 mb-1.5">
                  <Zap size={14} className="text-flag" />
                  <span className="text-xs font-bold text-flag uppercase tracking-wide">
                    Immediate Action (Contain Outage / Attack)
                  </span>
                </div>
                <p className="text-xs sm:text-[0.875rem] text-ink leading-relaxed">
                  {finding.recommended_remediation.immediate_action}
                </p>
              </div>

              {/* Long-Term Fix */}
              <div className="p-3.5 rounded-[12px] border border-ok-line/40 bg-ok-soft/20">
                <div className="flex items-center gap-2 mb-1.5">
                  <ShieldCheck size={14} className="text-ok" />
                  <span className="text-xs font-bold text-ok uppercase tracking-wide">
                    Long-Term Fix (Prevent Recurrence)
                  </span>
                </div>
                <p className="text-xs sm:text-[0.875rem] text-ink leading-relaxed">
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
