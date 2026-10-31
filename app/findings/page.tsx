"use client";

import { useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Wrench,
  Flame,
  Search,
  ArrowRight,
  ShieldCheck,
  Zap,
  Terminal,
  ArrowLeft,
} from "lucide-react";
import { Button, Chip, Panel, SectionTitle, Swatch, cn } from "@/components/ui";
import { useCapture } from "@/lib/context/CaptureContext";
import { Finding } from "@/lib/engine/types";

type FilterType = "ALL" | "ATTACK" | "FAULT" | "CRITICAL";

export default function FindingsPage() {
  const { analysisResult } = useCapture();
  const findings = analysisResult.report.findings;

  const [filter, setFilter] = useState<FilterType>("ALL");
  const [search, setSearch] = useState("");

  const attacksCount = findings.filter(f => f.category === "ATTACK").length;
  const faultsCount = findings.filter(f => f.category === "FAULT").length;
  const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;

  const filteredFindings = findings.filter(f => {
    const matchType =
      filter === "ALL"
        ? true
        : filter === "ATTACK"
        ? f.category === "ATTACK"
        : filter === "FAULT"
        ? f.category === "FAULT"
        : f.severity === "CRITICAL";

    const q = search.toLowerCase();
    const matchSearch =
      !q ||
      f.id.toLowerCase().includes(q) ||
      f.issue_title.toLowerCase().includes(q) ||
      f.plain_language_explanation.toLowerCase().includes(q) ||
      f.technical_details.root_cause.toLowerCase().includes(q);

    return matchType && matchSearch;
  });

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-6">
      {/* Top Breadcrumb & Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-rule">
        <div>
          <div className="flex items-center gap-2.5 text-sm text-ink-3 mb-1">
            <Link href="/" className="hover:text-brand hover:underline inline-flex items-center gap-1 font-medium">
              <ArrowLeft size={14} />
              <span>Dashboard</span>
            </Link>
            <span>/</span>
            <span className="text-ink font-semibold">Diagnostic Findings</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-ink">
            Diagnostic Findings &amp; Incident Triage
          </h1>
          <p className="text-sm sm:text-base text-ink-2 mt-1">
            Classified security attacks and operational outages with technical root causes, cited evidence, and remediation plans.
          </p>
        </div>

        {/* Search Field */}
        <div className="relative">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-ink-3" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings by keyword or ID..."
            className="pl-10 pr-4 py-2 bg-sunk rounded-xl text-sm text-ink border border-rule focus:outline-none focus:border-brand w-full sm:w-72"
          />
        </div>
      </div>

      {/* Filter Tabs (Pill style) */}
      <div className="flex items-center justify-between gap-4 overflow-x-auto pb-1">
        <div className="flex items-center gap-2 p-1.5 bg-sunk rounded-full border border-rule text-sm">
          <button
            type="button"
            onClick={() => setFilter("ALL")}
            className={cn(
              "px-4 py-1.5 rounded-full font-semibold transition-colors cursor-pointer text-sm",
              filter === "ALL" ? "bg-raised text-ink shadow-xs" : "text-ink-2 hover:text-ink"
            )}
          >
            All Findings ({findings.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter("ATTACK")}
            className={cn(
              "px-3.5 py-1 rounded-full font-semibold transition-colors cursor-pointer flex items-center gap-1.5 text-xs",
              filter === "ATTACK" ? "bg-brand-soft text-brand shadow-xs" : "text-ink-2 hover:text-ink"
            )}
          >
            <Swatch color="var(--color-flag)" />
            Attacks ({attacksCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter("FAULT")}
            className={cn(
              "px-3.5 py-1 rounded-full font-semibold transition-colors cursor-pointer flex items-center gap-1.5 text-xs",
              filter === "FAULT" ? "bg-brand-soft text-brand shadow-xs" : "text-ink-2 hover:text-ink"
            )}
          >
            <Swatch color="var(--color-warn)" />
            Faults ({faultsCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter("CRITICAL")}
            className={cn(
              "px-3.5 py-1 rounded-full font-semibold transition-colors cursor-pointer flex items-center gap-1.5 text-xs",
              filter === "CRITICAL" ? "bg-flag text-on-brand shadow-xs" : "text-ink-2 hover:text-flag"
            )}
          >
            <Flame size={12} />
            Critical Only ({criticalCount})
          </button>
        </div>
      </div>

      {/* Findings List */}
      {filteredFindings.length === 0 ? (
        <Panel className="p-12 text-center border-dashed border-rule-strong">
          <div className="h-12 w-12 rounded-full bg-ok-soft text-ok flex items-center justify-center mx-auto mb-3">
            <ShieldCheck size={24} />
          </div>
          <h3 className="font-bold text-base text-ink">No Findings Match Your Search</h3>
          <p className="text-xs sm:text-sm text-ink-2 max-w-md mx-auto mt-1">
            Try adjusting your search query or reset the category filters.
          </p>
          <Button variant="secondary" size="sm" onClick={() => { setFilter("ALL"); setSearch(""); }} className="mt-3">
            Reset Filters
          </Button>
        </Panel>
      ) : (
        <div className="space-y-4">
          {filteredFindings.map((finding) => {
            const isAttack = finding.category === "ATTACK";
            const isCritical = finding.severity === "CRITICAL";

            return (
              <Panel
                key={finding.id}
                className={cn(
                  "p-5 transition-all border",
                  isAttack && isCritical ? "border-flag-line hover:border-flag" : "border-rule hover:border-rule-strong"
                )}
              >
                {/* Header Row */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-rule-soft">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded-[6px] bg-sunk text-ink-2 border border-rule">
                      {finding.id}
                    </span>
                    <Chip tone={isAttack ? "flag" : "warn"}>
                      <Swatch color={isAttack ? "var(--color-flag)" : "var(--color-warn)"} />
                      {isAttack ? "Cyber Attack" : "Operational Fault"}
                    </Chip>
                    <Chip tone={isCritical ? "flag" : "warn"}>
                      {finding.severity}
                    </Chip>
                    <div className="inline-flex items-center gap-1.5 rounded-full border border-rule bg-sunk px-2.5 py-0.5 text-xs text-ink-2 font-mono">
                      <span>Confidence:</span>
                      <span className="font-bold text-ink">{finding.confidence_score}%</span>
                    </div>
                  </div>

                  <Link
                    href={`/findings/${finding.id}`}
                    className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1 cursor-pointer self-end sm:self-auto"
                  >
                    <span>Full Investigation Page</span>
                    <ArrowRight size={13} />
                  </Link>
                </div>

                {/* Content */}
                <div className="pt-3.5 space-y-3.5">
                  <Link href={`/findings/${finding.id}`} className="block group">
                    <h2 className="text-lg font-bold text-ink group-hover:text-brand transition-colors tracking-tight">
                      {finding.issue_title}
                    </h2>
                  </Link>

                  {/* Plain Language Explanation */}
                  <div className="p-3.5 rounded-[12px] bg-sunk/60 border border-rule-soft">
                    <span className="text-xs font-bold text-ink uppercase tracking-wide block mb-1">
                      Plain-Language Explanation (Beginner Friendly)
                    </span>
                    <p className="text-[0.9375rem] text-ink-2 leading-[1.55]">
                      {finding.plain_language_explanation}
                    </p>
                  </div>

                  {/* Root Cause & Evidence Preview */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    <div className="p-3 rounded-[10px] bg-raised border border-rule">
                      <span className="text-xs font-semibold text-ink-3 uppercase tracking-wider block mb-1">
                        Technical Root Cause
                      </span>
                      <p className="text-xs text-ink-2 leading-relaxed line-clamp-3">
                        {finding.technical_details.root_cause}
                      </p>
                    </div>

                    <div className="p-3 rounded-[10px] bg-raised border border-rule">
                      <span className="text-xs font-semibold text-ink-3 uppercase tracking-wider block mb-1">
                        Cited Evidence Frames ({finding.technical_details.evidence_packets.length})
                      </span>
                      <div className="space-y-1">
                        {finding.technical_details.evidence_packets.slice(0, 2).map((ev, i) => (
                          <div key={i} className="text-xs font-mono text-ink truncate flex items-center gap-1.5">
                            <Swatch color="var(--color-brand)" />
                            <span className="truncate">{ev}</span>
                          </div>
                        ))}
                      </div>
                      <Link
                        href={`/findings/${finding.id}`}
                        className="text-[11px] font-semibold text-brand hover:underline inline-block mt-2"
                      >
                        Inspect all {finding.technical_details.evidence_packets.length} evidence frames &rarr;
                      </Link>
                    </div>
                  </div>

                  {/* Action Link Footer */}
                  <div className="flex items-center justify-between pt-2 border-t border-rule-soft">
                    <span className="text-xs text-ink-3">
                      Dual remediation available (Immediate isolation + Long-term fix)
                    </span>
                    <Link
                      href={`/findings/${finding.id}`}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[8px] bg-brand text-on-brand text-xs font-semibold hover:bg-brand-deep transition-colors"
                    >
                      <span>Open Finding Dossier</span>
                      <ArrowRight size={13} />
                    </Link>
                  </div>
                </div>
              </Panel>
            );
          })}
        </div>
      )}
    </main>
  );
}
