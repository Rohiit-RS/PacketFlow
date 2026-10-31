"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ShieldAlert,
  ArrowRight,
  Layers,
  ArrowDownUp,
  FileJson,
  BookOpen,
  Wrench,
  Activity,
  CheckCircle2,
} from "lucide-react";
import { IngestionZone } from "@/components/IngestionZone";
import { SummaryHero } from "@/components/SummaryHero";
import { MetricsGrid } from "@/components/MetricsGrid";
import { Button, Chip, Panel, SectionTitle, Swatch, cn } from "@/components/ui";
import { useCapture } from "@/lib/context/CaptureContext";
import { formatBytes } from "@/lib/utils/formatters";
import { toast } from "sonner";

export default function Home() {
  const router = useRouter();
  const { analysisResult } = useCapture();
  const findings = analysisResult.report.findings;
  const flows = analysisResult.flows;
  const stats = analysisResult.stats;

  const copyDiagnosticJson = () => {
    try {
      navigator.clipboard.writeText(JSON.stringify(analysisResult.report, null, 2));
      toast.success("Diagnostic JSON copied to clipboard!");
    } catch {
      toast.error("Failed to copy JSON.");
    }
  };

  const scrollToFindings = () => {
    router.push("/findings");
  };

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-7">
      {/* Capture Ingestion & 1-Click Evaluation Bar */}
      <IngestionZone />

      {/* Executive Summary Hero Banner */}
      <SummaryHero
        summary={analysisResult.report.summary}
        onCopyJson={copyDiagnosticJson}
        onScrollToFindings={scrollToFindings}
      />

      {/* Metric Fact Cards */}
      <MetricsGrid stats={stats} flowsCount={flows.length} />

      {/* Main Two-Column Overview Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-2">
        {/* Left Column: Top Findings Preview */}
        <div className="lg:col-span-7 space-y-4">
          <SectionTitle
            sub="Active issues identified by the diagnostic engine"
            action={
              <Link
                href="/findings"
                className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1"
              >
                <span>View All Findings ({findings.length})</span>
                <ArrowRight size={13} />
              </Link>
            }
          >
            Diagnostic Findings Summary
          </SectionTitle>

          {findings.length === 0 ? (
            <Panel className="p-8 text-center border-dashed border-rule-strong">
              <div className="h-10 w-10 rounded-full bg-ok-soft text-ok flex items-center justify-center mx-auto mb-2.5">
                <CheckCircle2 size={22} />
              </div>
              <h3 className="font-bold text-sm text-ink">Zero Anomalies Detected</h3>
              <p className="text-xs text-ink-2 mt-0.5">
                All packet sequences adhere to standard RFC parameters with healthy RTT and zero drops.
              </p>
            </Panel>
          ) : (
            <div className="space-y-3">
              {findings.slice(0, 3).map((finding) => {
                const isAttack = finding.category === "ATTACK";
                const isCritical = finding.severity === "CRITICAL";

                return (
                  <Link
                    key={finding.id}
                    href={`/findings/${finding.id}`}
                    className="block group"
                  >
                    <Panel
                      className={cn(
                        "p-4 transition-all hover:border-brand cursor-pointer",
                        isAttack && isCritical ? "border-flag-line" : "border-rule"
                      )}
                    >
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded-[6px] bg-sunk text-ink-2 border border-rule">
                            {finding.id}
                          </span>
                          <Chip tone={isAttack ? "flag" : "warn"}>
                            <Swatch
                              color={isAttack ? "var(--color-flag)" : "var(--color-warn)"}
                            />
                            {isAttack ? "Cyber Attack" : "Operational Fault"}
                          </Chip>
                          <Chip tone={isCritical ? "flag" : "warn"}>
                            {finding.severity}
                          </Chip>
                        </div>
                        <span className="text-xs text-ink-3 font-mono">
                          {finding.confidence_score}% confidence
                        </span>
                      </div>

                      <h3 className="font-bold text-[0.97rem] text-ink group-hover:text-brand transition-colors line-clamp-1 mb-1">
                        {finding.issue_title}
                      </h3>
                      <p className="text-xs text-ink-2 line-clamp-2 leading-relaxed">
                        {finding.plain_language_explanation}
                      </p>

                      <div className="flex items-center justify-between pt-3 mt-3 border-t border-rule-soft text-xs">
                        <span className="text-ink-3">
                          {finding.technical_details.evidence_packets.length} cited evidence frame(s)
                        </span>
                        <span className="font-semibold text-brand inline-flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                          <span>Investigate Finding</span>
                          <ArrowRight size={13} />
                        </span>
                      </div>
                    </Panel>
                  </Link>
                );
              })}

              {findings.length > 3 && (
                <Link
                  href="/findings"
                  className="block p-3 rounded-[10px] bg-sunk/60 border border-rule text-center text-xs font-semibold text-brand hover:bg-sunk transition-colors"
                >
                  +{findings.length - 3} additional findings available in full list &rarr;
                </Link>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Protocol Breakdown & Quick Flow Preview */}
        <div className="lg:col-span-5 space-y-6">
          {/* Protocol Distribution */}
          <div>
            <SectionTitle sub="L3 / L4 protocol distribution">
              Protocols Breakdown
            </SectionTitle>
            <Panel className="p-4 space-y-3">
              <div className="space-y-2">
                {Object.entries(stats.protocols).map(([proto, count]) => {
                  const pct = Math.round((count / Math.max(1, stats.total_packets)) * 100);
                  const color =
                    proto === "TCP"
                      ? "var(--color-c-tcp)"
                      : proto === "DNS"
                      ? "var(--color-c-dns)"
                      : proto === "ARP"
                      ? "var(--color-c-routing)"
                      : "var(--color-c-other)";

                  return (
                    <div key={proto} className="space-y-1">
                      <div className="flex items-center justify-between text-xs font-semibold">
                        <div className="flex items-center gap-1.5">
                          <Swatch color={color} />
                          <span className="text-ink">{proto}</span>
                        </div>
                        <span className="text-ink-2 font-mono">
                          {count} pkts ({pct}%)
                        </span>
                      </div>
                      <div className="h-2 rounded-full bg-sunk overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{ width: `${pct}%`, backgroundColor: color }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </Panel>
          </div>

          {/* Flow Matrix Preview */}
          <div>
            <SectionTitle
              sub="Active network conversations"
              action={
                <Link
                  href="/flows"
                  className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1"
                >
                  <span>Flow Matrix ({flows.length})</span>
                  <ArrowRight size={13} />
                </Link>
              }
            >
              Conversation Streams
            </SectionTitle>
            <Panel className="overflow-hidden">
              <div className="divide-y divide-rule-soft text-xs font-mono">
                {flows.slice(0, 4).map((f) => (
                  <div key={f.id} className="p-3 flex items-center justify-between hover:bg-sunk/50 transition-colors">
                    <div className="truncate max-w-[200px]">
                      <div className="font-semibold text-ink truncate">{f.source}</div>
                      <div className="text-ink-3 truncate">&darr; {f.destination}</div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-ink font-semibold">{f.packets_count} pkts</div>
                      <div className="text-ink-3 text-[11px]">{formatBytes(f.bytes_count)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          {/* Quick Tool Links */}
          <div className="grid grid-cols-2 gap-3 pt-1">
            <Link href="/topology" className="block group">
              <Panel className="p-3.5 hover:border-brand transition-colors text-xs">
                <div className="flex items-center gap-1.5 font-bold text-ink mb-1 group-hover:text-brand">
                  <Activity size={14} className="text-brand" />
                  <span>Threat Topology</span>
                </div>
                <p className="text-ink-2 text-[11px] line-clamp-2">
                  Interactive node-link graph with animated threat vectors.
                </p>
              </Panel>
            </Link>

            <Link href="/remediation" className="block group">
              <Panel className="p-3.5 hover:border-brand transition-colors text-xs">
                <div className="flex items-center gap-1.5 font-bold text-ink mb-1 group-hover:text-brand">
                  <Wrench size={14} className="text-ok" />
                  <span>Automated Fixes</span>
                </div>
                <p className="text-ink-2 text-[11px] line-clamp-2">
                  Generate iptables scripts, Snort rules, and Cisco configs.
                </p>
              </Panel>
            </Link>

            <Link href="/report" className="block group">
              <Panel className="p-3.5 hover:border-brand transition-colors text-xs">
                <div className="flex items-center gap-1.5 font-bold text-ink mb-1 group-hover:text-brand">
                  <ShieldAlert size={14} className="text-flag" />
                  <span>Forensic Audit</span>
                </div>
                <p className="text-ink-2 text-[11px] line-clamp-2">
                  Executive PDF-ready incident report with SHA-256 hash.
                </p>
              </Panel>
            </Link>

            <Link href="/schema" className="block group">
              <Panel className="p-3.5 hover:border-brand transition-colors text-xs">
                <div className="flex items-center gap-1.5 font-bold text-ink mb-1 group-hover:text-brand">
                  <FileJson size={14} className="text-brand" />
                  <span>Strict JSON API</span>
                </div>
                <p className="text-ink-2 text-[11px] line-clamp-2">
                  Live JSON schema output and offline REST endpoint.
                </p>
              </Panel>
            </Link>
          </div>
        </div>
      </div>
    </main>
  );
}
