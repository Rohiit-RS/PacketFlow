"use client";

import { use } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  ShieldAlert,
  Wrench,
  Zap,
  ShieldCheck,
  Terminal,
  Info,
  Clock,
  ArrowRight,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { Button, Chip, Panel, SectionTitle, Swatch, cn } from "@/components/ui";
import { useCapture } from "@/lib/context/CaptureContext";

interface FindingPageProps {
  params: Promise<{ id: string }>;
}

export default function FindingDetailPage({ params }: FindingPageProps) {
  const resolvedParams = use(params);
  const findingId = decodeURIComponent(resolvedParams.id);
  const { analysisResult, getFindingById } = useCapture();

  const finding = getFindingById(findingId);
  const allFindings = analysisResult.report.findings;

  const currentIndex = allFindings.findIndex(
    f => f.id.toLowerCase() === findingId.toLowerCase()
  );
  const prevFinding = currentIndex > 0 ? allFindings[currentIndex - 1] : null;
  const nextFinding = currentIndex < allFindings.length - 1 ? allFindings[currentIndex + 1] : null;

  if (!finding) {
    return (
      <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-12 text-center">
        <Panel className="p-12 max-w-lg mx-auto">
          <div className="h-12 w-12 rounded-full bg-warn-soft text-warn flex items-center justify-center mx-auto mb-3">
            <Info size={24} />
          </div>
          <h1 className="text-xl font-bold text-ink mb-1">Finding Not Found</h1>
          <p className="text-sm text-ink-2 mb-6">
            The requested finding ID <code className="font-mono text-brand">{findingId}</code> does not exist in the active capture.
          </p>
          <Link href="/findings">
            <Button variant="primary" size="md">
              &larr; Return to Findings List
            </Button>
          </Link>
        </Panel>
      </main>
    );
  }

  const isAttack = finding.category === "ATTACK";
  const isCritical = finding.severity === "CRITICAL";

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-6">
      {/* Top Breadcrumb Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-rule">
        <div className="flex items-center gap-2 text-xs text-ink-3">
          <Link href="/" className="hover:text-brand hover:underline">
            Overview
          </Link>
          <span>/</span>
          <Link href="/findings" className="hover:text-brand hover:underline">
            Findings
          </Link>
          <span>/</span>
          <span className="text-ink font-mono font-semibold">{finding.id}</span>
        </div>

        {/* Previous / Next Pager */}
        <div className="flex items-center gap-2">
          {prevFinding && (
            <Link
              href={`/findings/${prevFinding.id}`}
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-[8px] bg-sunk text-ink-2 hover:text-ink text-xs font-semibold border border-rule transition-colors"
            >
              <ChevronLeft size={13} />
              <span>{prevFinding.id}</span>
            </Link>
          )}
          {nextFinding && (
            <Link
              href={`/findings/${nextFinding.id}`}
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-[8px] bg-sunk text-ink-2 hover:text-ink text-xs font-semibold border border-rule transition-colors"
            >
              <span>{nextFinding.id}</span>
              <ChevronRight size={13} />
            </Link>
          )}
        </div>
      </div>

      {/* Main Dossier Header Panel */}
      <Panel className={cn("p-6 border-l-[5px]", isAttack ? "border-l-flag" : "border-l-warn")}>
        <div className="flex flex-wrap items-center gap-2.5 mb-3">
          <span className="font-mono text-xs font-bold px-2.5 py-0.5 rounded-[6px] bg-sunk text-ink border border-rule">
            {finding.id}
          </span>
          <Chip tone={isAttack ? "flag" : "warn"}>
            <Swatch color={isAttack ? "var(--color-flag)" : "var(--color-warn)"} />
            {isAttack ? "Malicious Cyber Attack" : "Operational Network Fault"}
          </Chip>
          <Chip tone={isCritical ? "flag" : "warn"}>
            {finding.severity} SEVERITY
          </Chip>
          <div className="inline-flex items-center gap-1.5 rounded-full border border-rule bg-sunk px-3 py-0.5 text-xs text-ink-2 font-mono">
            <span>Diagnostic Confidence:</span>
            <span className="font-bold text-ok">{finding.confidence_score}%</span>
          </div>

          {finding.mitre_technique && (
            <a
              href={finding.mitre_technique.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-0.5 text-xs text-red-600 font-mono hover:underline"
            >
              <span>MITRE: {finding.mitre_technique.id} ({finding.mitre_technique.name})</span>
              <ExternalLink size={10} />
            </a>
          )}

          {finding.cwe && (
            <a
              href={finding.cwe.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-0.5 text-xs text-blue-600 font-mono hover:underline"
            >
              <span>{finding.cwe.id}</span>
              <ExternalLink size={10} />
            </a>
          )}
        </div>

        <h1 className="text-2xl sm:text-3xl font-bold tracking-[-0.022em] text-ink mb-3">
          {finding.issue_title}
        </h1>

        {/* Beginner Plain-Language Explanation */}
        <div className="p-4 rounded-[12px] bg-sunk/70 border border-rule-soft space-y-1">
          <div className="flex items-center gap-2 text-xs font-bold text-ink uppercase tracking-wider">
            <Info size={15} className="text-brand" />
            <span>Plain-Language Explanation (Non-Expert Guide)</span>
          </div>
          <p className="text-[1rem] text-ink-2 leading-[1.6]">
            {finding.plain_language_explanation}
          </p>
        </div>
      </Panel>

      {/* Technical Breakdown & Root Cause */}
      <Panel className="p-6 space-y-4">
        <SectionTitle sub="Low-level protocol state breakdown and anomaly indicators">
          Technical Root Cause Analysis
        </SectionTitle>

        <p className="text-[0.95rem] text-ink-2 leading-[1.65] p-4 rounded-[10px] bg-raised border border-rule">
          {finding.technical_details.root_cause}
        </p>
      </Panel>

      {/* Cited Evidence Packets */}
      <Panel className="p-6 space-y-4">
        <div className="flex items-center justify-between">
          <SectionTitle sub="Specific packets, frames, and IP associations verifying this finding">
            Cited Telemetry Evidence ({finding.technical_details.evidence_packets.length})
          </SectionTitle>
          <Link
            href="/packets"
            className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1"
          >
            <span>Open All in Packet Inspector</span>
            <ExternalLink size={13} />
          </Link>
        </div>

        <div className="space-y-2">
          {finding.technical_details.evidence_packets.map((ev: string, idx: number) => {
            const frameMatch = ev.match(/Frame #(\d+)/);
            const frameNum = frameMatch ? frameMatch[1] : null;

            return (
              <div
                key={idx}
                className="p-3 rounded-[10px] bg-sunk/50 border border-rule font-mono text-xs text-ink flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-rule-strong hover:bg-sunk transition-colors"
              >
                <div className="flex items-center gap-2.5 truncate">
                  <Swatch color="var(--color-brand)" />
                  <span className="font-semibold truncate">{ev}</span>
                </div>

                {frameNum ? (
                  <Link
                    href={`/packets?frame=${frameNum}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-[6px] bg-brand text-on-brand text-[11px] font-sans font-semibold hover:bg-brand-deep transition-colors shrink-0"
                  >
                    <Terminal size={12} />
                    <span>Inspect Frame #{frameNum}</span>
                    <ArrowRight size={12} />
                  </Link>
                ) : (
                  <span className="text-[11px] text-ink-3 font-sans">Correlated Log Marker</span>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      {/* Dual Remediation Action Plan */}
      <Panel className="p-6 space-y-4">
        <SectionTitle sub="Step-by-step resolution strategy to triage impact and prevent recurrence">
          Recommended Remediation Strategy
        </SectionTitle>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Immediate Action */}
          <div className="p-5 rounded-[12px] border border-flag-line bg-flag-soft/25 space-y-2">
            <div className="flex items-center gap-2">
              <Zap size={16} className="text-flag" />
              <h3 className="font-bold text-sm text-flag uppercase tracking-wide">
                Immediate Action (Step 1: Triage &amp; Isolate)
              </h3>
            </div>
            <p className="text-[0.9375rem] text-ink leading-relaxed">
              {finding.recommended_remediation.immediate_action}
            </p>
          </div>

          {/* Long-Term Fix */}
          <div className="p-5 rounded-[12px] border border-ok-line bg-ok-soft/25 space-y-2">
            <div className="flex items-center gap-2">
              <ShieldCheck size={16} className="text-ok" />
              <h3 className="font-bold text-sm text-ok uppercase tracking-wide">
                Long-Term Fix (Step 2: Architecture Hardening)
              </h3>
            </div>
            <p className="text-[0.9375rem] text-ink leading-relaxed">
              {finding.recommended_remediation.long_term_fix}
            </p>
          </div>
        </div>
      </Panel>

      {/* Enterprise Defensive Rule Snippets */}
      {finding.remediation_rules && (
        <Panel className="p-6 space-y-4">
          <div className="flex items-center justify-between">
            <SectionTitle sub="Synthesized machine-readable rules for immediate perimeter enforcement">
              Generated Defense Signatures &amp; Firewall Rules
            </SectionTitle>
            <Link
              href="/remediation"
              className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1"
            >
              <span>View Full Incident Remediation</span>
              <ExternalLink size={13} />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {finding.remediation_rules.iptables && (
              <div className="p-4 bg-sunk rounded-[10px] border border-rule space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-bold font-mono text-ink uppercase">
                  <Terminal size={14} className="text-brand" />
                  <span>Linux iptables / sysctl</span>
                </div>
                <pre className="p-2.5 rounded-[6px] bg-canvas border border-rule font-mono text-[11px] text-ink overflow-x-auto whitespace-pre">
                  {finding.remediation_rules.iptables}
                </pre>
              </div>
            )}

            {finding.remediation_rules.snort && (
              <div className="p-4 bg-sunk rounded-[10px] border border-rule space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-bold font-mono text-ink uppercase">
                  <ShieldCheck size={14} className="text-ok" />
                  <span>Snort / Suricata IDS Signature</span>
                </div>
                <pre className="p-2.5 rounded-[6px] bg-canvas border border-rule font-mono text-[11px] text-ink overflow-x-auto whitespace-pre">
                  {finding.remediation_rules.snort}
                </pre>
              </div>
            )}

            {finding.remediation_rules.cisco && (
              <div className="p-4 bg-sunk rounded-[10px] border border-rule space-y-2 md:col-span-2">
                <div className="flex items-center gap-1.5 text-xs font-bold font-mono text-ink uppercase">
                  <Wrench size={14} className="text-blue-600" />
                  <span>Cisco Switch / Router IOS Hardening</span>
                </div>
                <pre className="p-2.5 rounded-[6px] bg-canvas border border-rule font-mono text-[11px] text-ink overflow-x-auto whitespace-pre">
                  {finding.remediation_rules.cisco}
                </pre>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* Back Button Footer */}
      <div className="pt-2 flex justify-between items-center">
        <Link href="/findings">
          <Button variant="secondary" size="md">
            &larr; Back to All Findings
          </Button>
        </Link>
        <Link href="/packets">
          <Button variant="primary" size="md">
            <span>Explore Raw Packet Stream</span>
            <ArrowRight size={15} />
          </Button>
        </Link>
      </div>
    </main>
  );
}
