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
  FileText,
  Network,
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
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-8 space-y-8">
      {/* Capture Ingestion & 1-Click Evaluation Bar */}
      <IngestionZone />

      {/* Executive Summary Hero Banner */}
      <SummaryHero
        summary={analysisResult.report.summary}
        onCopyJson={copyDiagnosticJson}
        onScrollToFindings={scrollToFindings}
      />

      {/* Metric Fact Cards - Symmetric 4-Column Grid */}
      <MetricsGrid stats={stats} flowsCount={flows.length} />

      {/* Symmetric Two-Column Overview Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
        {/* Left Symmetric Box: Diagnostic Findings */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs">
          <div>
            <div className="flex items-center justify-between gap-3 mb-6 pb-4 border-b border-rule">
              <div>
                <h2 className="text-xl font-bold tracking-tight text-ink">
                  Diagnostic Findings
                </h2>
                <p className="text-sm text-ink-2 mt-0.5">
                  Categorized operational outages and active threat anomalies
                </p>
              </div>

              <Link
                href="/findings"
                className="text-sm font-semibold text-brand hover:underline inline-flex items-center gap-1.5"
              >
                <span>View All ({findings.length})</span>
                <ArrowRight size={15} />
              </Link>
            </div>

            {findings.length === 0 ? (
              <div className="py-16 text-center">
                <div className="h-12 w-12 rounded-full bg-ok-soft text-ok flex items-center justify-center mx-auto mb-3">
                  <CheckCircle2 size={24} />
                </div>
                <h3 className="font-bold text-base text-ink">Zero Anomalies Detected</h3>
                <p className="text-sm text-ink-2 mt-1">
                  All packet sequences adhere to standard RFC parameters with healthy RTT and zero drops.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {findings.slice(0, 3).map((finding) => {
                  const isAttack = finding.category === "ATTACK";
                  const isCritical = finding.severity === "CRITICAL";

                  return (
                    <Link
                      key={finding.id}
                      href={`/findings/${finding.id}`}
                      className="block group"
                    >
                      <div
                        className={cn(
                          "p-4 rounded-xl border transition-all hover:border-brand bg-canvas/60 hover:bg-canvas shadow-2xs",
                          isAttack && isCritical ? "border-l-4 border-l-flag border-rule" : "border-rule"
                        )}
                      >
                        <div className="flex items-center justify-between gap-2 mb-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold px-2.5 py-0.5 rounded-md bg-sunk text-ink border border-rule-soft">
                              {finding.id}
                            </span>
                            <Chip tone={isAttack ? "flag" : "warn"}>
                              <Swatch
                                color={isAttack ? "var(--color-flag)" : "var(--color-warn)"}
                                className="w-2 h-2 rounded-full"
                              />
                              {isAttack ? "Attack" : "Fault"}
                            </Chip>
                            <Chip tone={isCritical ? "flag" : "warn"}>
                              {finding.severity}
                            </Chip>
                          </div>
                          <span className="text-xs text-ink-3 font-mono font-medium">
                            {finding.confidence_score}% confidence
                          </span>
                        </div>

                        <h3 className="font-bold text-base text-ink group-hover:text-brand transition-colors line-clamp-1 mb-1">
                          {finding.issue_title}
                        </h3>
                        <p className="text-sm text-ink-2 line-clamp-2 leading-relaxed">
                          {finding.plain_language_explanation}
                        </p>
                      </div>
                    </Link>
                  );
                })}
              </div>
            )}
          </div>

          <div className="pt-6 border-t border-rule mt-6">
            <Link
              href="/findings"
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-sunk hover:bg-raised-hover border border-rule text-sm font-semibold text-ink transition-colors"
            >
              <span>Explore All {findings.length} Findings in Dossier Catalog</span>
              <ArrowRight size={15} />
            </Link>
          </div>
        </Panel>

        {/* Right Symmetric Box: Conversation Streams & Protocol Breakdown */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs">
          <div>
            <div className="flex items-center justify-between gap-3 mb-6 pb-4 border-b border-rule">
              <div>
                <h2 className="text-xl font-bold tracking-tight text-ink">
                  Conversation Streams
                </h2>
                <p className="text-sm text-ink-2 mt-0.5">
                  Reconstructed bidirectional host communication pairs
                </p>
              </div>

              <Link
                href="/flows"
                className="text-sm font-semibold text-brand hover:underline inline-flex items-center gap-1.5"
              >
                <span>Flow Matrix ({flows.length})</span>
                <ArrowRight size={15} />
              </Link>
            </div>

            {/* Conversation Flows Table */}
            <div className="space-y-3">
              {flows.slice(0, 4).map((f) => (
                <div
                  key={f.id}
                  className="p-3.5 rounded-xl bg-canvas/60 border border-rule flex items-center justify-between text-sm font-mono hover:bg-canvas transition-colors"
                >
                  <div className="truncate max-w-[240px]">
                    <div className="font-bold text-ink truncate">{f.source}</div>
                    <div className="text-ink-3 text-xs truncate">&rarr; {f.destination}</div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-ink font-bold">{f.packets_count} pkts</div>
                    <div className="text-ink-3 text-xs">{formatBytes(f.bytes_count)}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Protocol Distribution Summary */}
            <div className="pt-6 mt-6 border-t border-rule">
              <span className="text-xs uppercase tracking-wider font-bold text-ink-3 block mb-3">
                Protocol Composition
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {Object.entries(stats.protocols).slice(0, 4).map(([proto, count]) => {
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
                    <div key={proto} className="p-3 rounded-lg bg-sunk/60 border border-rule-soft">
                      <div className="flex items-center gap-1.5 text-xs font-semibold text-ink mb-1">
                        <Swatch color={color} className="w-2 h-2 rounded-full" />
                        <span>{proto}</span>
                      </div>
                      <div className="text-base font-bold font-mono text-ink">
                        {pct}%
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="pt-6 border-t border-rule mt-6">
            <Link
              href="/packets"
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl bg-brand text-on-brand text-sm font-semibold hover:bg-brand-deep transition-colors"
            >
              <span>Inspect Raw Packet Frames &amp; Hex Payloads</span>
              <ArrowRight size={15} />
            </Link>
          </div>
        </Panel>
      </div>

      {/* Symmetric 3-Card Enterprise Action Hub */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
        <Link href="/topology" className="block group h-full">
          <Panel className="p-6 h-full flex flex-col justify-between hover:border-brand transition-all border border-rule shadow-xs">
            <div>
              <div className="h-12 w-12 rounded-xl bg-brand-soft text-brand flex items-center justify-center mb-4">
                <Network size={24} />
              </div>
              <h3 className="text-lg font-bold text-ink group-hover:text-brand transition-colors">
                Threat Topology
              </h3>
              <p className="text-sm text-ink-2 mt-1.5 leading-relaxed">
                Visual node-link communication matrix with animated traffic vectors and threat indicators.
              </p>
            </div>
            <div className="pt-4 border-t border-rule-soft mt-4 flex items-center text-sm font-semibold text-brand">
              <span>Launch Topology Map</span>
              <ArrowRight size={15} className="ml-1.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Panel>
        </Link>

        <Link href="/remediation" className="block group h-full">
          <Panel className="p-6 h-full flex flex-col justify-between hover:border-brand transition-all border border-rule shadow-xs">
            <div>
              <div className="h-12 w-12 rounded-xl bg-ok-soft text-ok flex items-center justify-center mb-4">
                <Wrench size={24} />
              </div>
              <h3 className="text-lg font-bold text-ink group-hover:text-brand transition-colors">
                Automated Remediation
              </h3>
              <p className="text-sm text-ink-2 mt-1.5 leading-relaxed">
                Auto-generate executable Linux iptables scripts, Snort/Suricata IDS rules, and Cisco switch configs.
              </p>
            </div>
            <div className="pt-4 border-t border-rule-soft mt-4 flex items-center text-sm font-semibold text-brand">
              <span>View Defense Scripts</span>
              <ArrowRight size={15} className="ml-1.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Panel>
        </Link>

        <Link href="/report" className="block group h-full">
          <Panel className="p-6 h-full flex flex-col justify-between hover:border-brand transition-all border border-rule shadow-xs">
            <div>
              <div className="h-12 w-12 rounded-xl bg-warn-soft text-warn flex items-center justify-center mb-4">
                <FileText size={24} />
              </div>
              <h3 className="text-lg font-bold text-ink group-hover:text-brand transition-colors">
                Forensic Audit Report
              </h3>
              <p className="text-sm text-ink-2 mt-1.5 leading-relaxed">
                Print/PDF-ready incident audit report with SHA-256 evidence integrity and MITRE ATT&CK mapping.
              </p>
            </div>
            <div className="pt-4 border-t border-rule-soft mt-4 flex items-center text-sm font-semibold text-brand">
              <span>Open Audit Document</span>
              <ArrowRight size={15} className="ml-1.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Panel>
        </Link>
      </div>
    </main>
  );
}
