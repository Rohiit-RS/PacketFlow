"use client";

import { use } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
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
      <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-16 text-center">
        <Panel className="p-12 max-w-lg mx-auto shadow-sm">
          <div className="h-14 w-14 rounded-full bg-warn-soft text-warn flex items-center justify-center mx-auto mb-4">
            <Info size={28} />
          </div>
          <h1 className="text-2xl font-bold text-ink mb-2">Finding Not Found</h1>
          <p className="text-base text-ink-2 mb-6">
            The requested finding ID <code className="font-mono text-brand font-bold">{findingId}</code> was not found in this capture.
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
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-8 space-y-8">
      {/* Top Breadcrumb Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-rule">
        <div className="flex items-center gap-2.5 text-sm text-ink-3">
          <Link href="/" className="hover:text-brand hover:underline font-medium">
            Dashboard
          </Link>
          <span>/</span>
          <Link href="/findings" className="hover:text-brand hover:underline font-medium">
            Findings
          </Link>
          <span>/</span>
          <span className="text-ink font-mono font-bold">{finding.id}</span>
        </div>

        {/* Previous / Next Pager */}
        <div className="flex items-center gap-2">
          {prevFinding && (
            <Link
              href={`/findings/${prevFinding.id}`}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-sunk text-ink hover:text-brand text-xs font-semibold border border-rule transition-colors"
            >
              <ChevronLeft size={14} />
              <span>{prevFinding.id}</span>
            </Link>
          )}
          {nextFinding && (
            <Link
              href={`/findings/${nextFinding.id}`}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-sunk text-ink hover:text-brand text-xs font-semibold border border-rule transition-colors"
            >
              <span>{nextFinding.id}</span>
              <ChevronRight size={14} />
            </Link>
          )}
        </div>
      </div>

      {/* Main Dossier Header Panel */}
      <Panel className={cn("p-8 lg:p-10 border shadow-xs", isAttack ? "border-l-[6px] border-l-flag border-rule" : "border-l-[6px] border-l-warn border-rule")}>
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <span className="font-mono text-sm font-bold px-3 py-1 rounded-lg bg-sunk text-ink border border-rule">
            {finding.id}
          </span>
          <Chip tone={isAttack ? "flag" : "warn"}>
            <Swatch color={isAttack ? "var(--color-flag)" : "var(--color-warn)"} className="w-2.5 h-2.5 rounded-full" />
            {isAttack ? "Malicious Cyber Attack" : "Operational Network Fault"}
          </Chip>
          <Chip tone={isCritical ? "flag" : "warn"}>
            {finding.severity} SEVERITY
          </Chip>
          <div className="inline-flex items-center gap-1.5 rounded-full border border-rule bg-sunk px-3 py-1 text-xs text-ink-2 font-mono font-medium">
            <span>Diagnostic Confidence:</span>
            <span className="font-bold text-ok">{finding.confidence_score}%</span>
          </div>

          {finding.mitre_technique && (
            <a
              href={finding.mitre_technique.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 text-xs text-red-600 font-mono hover:underline font-bold"
            >
              <span>MITRE: {finding.mitre_technique.id} ({finding.mitre_technique.name})</span>
              <ExternalLink size={11} />
            </a>
          )}

          {finding.cwe && (
            <a
              href={finding.cwe.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs text-blue-600 font-mono hover:underline font-bold"
            >
              <span>{finding.cwe.id}</span>
              <ExternalLink size={11} />
            </a>
          )}
        </div>

        <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-[-0.025em] text-ink mb-4">
          {finding.issue_title}
        </h1>

        {/* Beginner Plain-Language Explanation */}
        <div className="p-6 rounded-2xl bg-sunk/60 border border-rule-soft space-y-2">
          <div className="flex items-center gap-2 text-xs font-bold text-ink uppercase tracking-wider">
            <Info size={16} className="text-brand" />
            <span>Plain-Language Explanation (Non-Expert Guide)</span>
          </div>
          <p className="text-base sm:text-lg text-ink-2 leading-relaxed font-normal">
            {finding.plain_language_explanation}
          </p>
        </div>

        {/* Causal Correlation Callout */}
        {finding.correlation && (
          <div className={cn(
            "p-6 rounded-2xl border flex items-start gap-4 transition-colors",
            finding.correlation.relation_type === "INDUCED_COLLATERAL_DAMAGE"
              ? "bg-amber-500/10 border-amber-500/30 text-ink"
              : "bg-red-500/10 border-red-500/30 text-ink"
          )}>
            <Zap size={22} className={finding.correlation.relation_type === "INDUCED_COLLATERAL_DAMAGE" ? "text-amber-500 shrink-0 mt-0.5" : "text-flag shrink-0 mt-0.5"} />
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className={cn(
                  "text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-md font-mono",
                  finding.correlation.relation_type === "INDUCED_COLLATERAL_DAMAGE"
                    ? "bg-amber-500/20 text-amber-600 dark:text-amber-400"
                    : "bg-red-500/20 text-red-600 dark:text-red-400"
                )}>
                  {finding.correlation.relation_type === "INDUCED_COLLATERAL_DAMAGE" ? "⚡ Induced Collateral Symptom" : "🎯 Root Cause Driver"}
                </span>
                <Link
                  href={`/findings/${finding.correlation.related_finding_id}`}
                  className="text-xs font-mono font-bold text-brand hover:underline inline-flex items-center gap-1"
                >
                  Correlated with {finding.correlation.related_finding_id}
                  <ArrowRight size={12} />
                </Link>
              </div>
              <p className="text-base text-ink-2 leading-relaxed font-medium">
                {finding.correlation.explanation}
              </p>
            </div>
          </div>
        )}
      </Panel>

      {/* Technical Breakdown & Root Cause */}
      <Panel className="p-8 space-y-4 border border-rule shadow-xs">
        <SectionTitle sub="Low-level protocol state breakdown and anomaly indicators">
          Technical Root Cause Analysis
        </SectionTitle>

        <p className="text-base text-ink-2 leading-relaxed p-6 rounded-xl bg-raised border border-rule font-normal">
          {finding.technical_details.root_cause}
        </p>
      </Panel>

      {/* Cited Evidence Packets */}
      <Panel className="p-8 space-y-4 border border-rule shadow-xs">
        <div className="flex items-center justify-between">
          <SectionTitle sub="Specific packets, frames, and IP associations verifying this finding">
            Cited Telemetry Evidence ({finding.technical_details.evidence_packets.length})
          </SectionTitle>
          <Link
            href="/packets"
            className="text-sm font-semibold text-brand hover:underline inline-flex items-center gap-1"
          >
            <span>Open All in Packet Inspector</span>
            <ExternalLink size={14} />
          </Link>
        </div>

        <div className="space-y-2.5">
          {finding.technical_details.evidence_packets.map((ev: string, idx: number) => {
            const frameMatch = ev.match(/Frame #(\d+)/);
            const frameNum = frameMatch ? frameMatch[1] : null;

            return (
              <div
                key={idx}
                className="p-3.5 rounded-xl bg-sunk/50 border border-rule font-mono text-sm text-ink flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-rule-strong hover:bg-sunk transition-colors"
              >
                <div className="flex items-center gap-3 truncate">
                  <Swatch color="var(--color-brand)" className="w-2.5 h-2.5 rounded-full" />
                  <span className="font-semibold truncate">{ev}</span>
                </div>

                {frameNum ? (
                  <Link
                    href={`/packets?frame=${frameNum}`}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-brand text-on-brand text-xs font-sans font-semibold hover:bg-brand-deep transition-colors shrink-0"
                  >
                    <Terminal size={13} />
                    <span>Inspect Frame #{frameNum}</span>
                    <ArrowRight size={13} />
                  </Link>
                ) : (
                  <span className="text-xs text-ink-3 font-sans">Correlated Log Marker</span>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      {/* Symmetric Dual Remediation Action Plan */}
      <Panel className="p-8 space-y-5 border border-rule shadow-xs">
        <SectionTitle sub="Step-by-step resolution strategy to triage impact and prevent recurrence">
          Recommended Remediation Strategy
        </SectionTitle>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
          {/* Immediate Action (Equal Height) */}
          <div className="p-6 rounded-2xl border border-flag-line bg-flag-soft/25 flex flex-col justify-start h-full space-y-2.5">
            <div className="flex items-center gap-2">
              <Zap size={18} className="text-flag" />
              <h3 className="font-bold text-sm text-flag uppercase tracking-wide">
                Immediate Action (Step 1: Triage &amp; Isolate)
              </h3>
            </div>
            <p className="text-base text-ink leading-relaxed font-normal">
              {finding.recommended_remediation.immediate_action}
            </p>
          </div>

          {/* Long-Term Fix (Equal Height) */}
          <div className="p-6 rounded-2xl border border-ok-line bg-ok-soft/25 flex flex-col justify-start h-full space-y-2.5">
            <div className="flex items-center gap-2">
              <ShieldCheck size={18} className="text-ok" />
              <h3 className="font-bold text-sm text-ok uppercase tracking-wide">
                Long-Term Fix (Step 2: Architecture Hardening)
              </h3>
            </div>
            <p className="text-base text-ink leading-relaxed font-normal">
              {finding.recommended_remediation.long_term_fix}
            </p>
          </div>
        </div>
      </Panel>

      {/* Symmetric Defensive Rule Snippets */}
      {finding.remediation_rules && (
        <Panel className="p-8 space-y-5 border border-rule shadow-xs">
          <div className="flex items-center justify-between">
            <SectionTitle sub="Synthesized machine-readable rules for immediate perimeter enforcement">
              Generated Defense Signatures &amp; Firewall Rules
            </SectionTitle>
            <Link
              href="/remediation"
              className="text-sm font-semibold text-brand hover:underline inline-flex items-center gap-1"
            >
              <span>View Full Incident Remediation</span>
              <ExternalLink size={14} />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
            {finding.remediation_rules.iptables && (
              <div className="p-5 bg-sunk rounded-xl border border-rule flex flex-col justify-between h-full space-y-3">
                <div className="flex items-center gap-2 text-xs font-bold font-mono text-ink uppercase">
                  <Terminal size={15} className="text-brand" />
                  <span>Linux iptables / sysctl</span>
                </div>
                <pre className="p-3 rounded-lg bg-canvas border border-rule font-mono text-xs text-ink overflow-x-auto whitespace-pre leading-relaxed">
                  {finding.remediation_rules.iptables}
                </pre>
              </div>
            )}

            {finding.remediation_rules.snort && (
              <div className="p-5 bg-sunk rounded-xl border border-rule flex flex-col justify-between h-full space-y-3">
                <div className="flex items-center gap-2 text-xs font-bold font-mono text-ink uppercase">
                  <ShieldCheck size={15} className="text-ok" />
                  <span>Snort / Suricata IDS Signature</span>
                </div>
                <pre className="p-3 rounded-lg bg-canvas border border-rule font-mono text-xs text-ink overflow-x-auto whitespace-pre leading-relaxed">
                  {finding.remediation_rules.snort}
                </pre>
              </div>
            )}

            {finding.remediation_rules.cisco && (
              <div className="p-5 bg-sunk rounded-xl border border-rule flex flex-col justify-between h-full space-y-3 md:col-span-2">
                <div className="flex items-center gap-2 text-xs font-bold font-mono text-ink uppercase">
                  <Wrench size={15} className="text-blue-600" />
                  <span>Cisco Switch / Router IOS Hardening</span>
                </div>
                <pre className="p-3 rounded-lg bg-canvas border border-rule font-mono text-xs text-ink overflow-x-auto whitespace-pre leading-relaxed">
                  {finding.remediation_rules.cisco}
                </pre>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* Back Button Footer */}
      <div className="pt-4 flex justify-between items-center">
        <Link href="/findings">
          <Button variant="secondary" size="md">
            &larr; Back to All Findings
          </Button>
        </Link>
        <Link href="/packets">
          <Button variant="primary" size="md">
            <span>Explore Raw Packet Stream</span>
            <ArrowRight size={16} />
          </Button>
        </Link>
      </div>
    </main>
  );
}
