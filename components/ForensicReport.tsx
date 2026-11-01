"use client";

import React from "react";
import Link from "next/link";
import {
  FileText,
  Printer,
  ShieldCheck,
  ShieldAlert,
  Hash,
  Clock,
  Layers,
  ArrowRight,
  ExternalLink,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Download,
} from "lucide-react";
import { Button, Chip, Swatch, cn } from "./ui";
import { AnalysisEngineResult } from "@/lib/engine/types";
import { formatBytes } from "@/lib/utils/formatters";

interface ForensicReportProps {
  analysisResult: AnalysisEngineResult;
  captureName: string;
}

export function ForensicReport({ analysisResult, captureName }: ForensicReportProps) {
  const { report, packets, flows, stats } = analysisResult;
  const { summary, findings } = report;

  const handlePrint = () => {
    // Immediate pre-print safety hide for website header and footer
    const elementsToHide = document.querySelectorAll("header, footer, nav, aside, .no-print, [data-no-print]");
    elementsToHide.forEach((el) => {
      (el as HTMLElement).style.setProperty("display", "none", "important");
    });

    window.print();

    // Restore after print dialog closes
    setTimeout(() => {
      elementsToHide.forEach((el) => {
        (el as HTMLElement).style.removeProperty("display");
      });
    }, 1000);
  };

  // Calculate composite risk score (0-100)
  const riskScore = React.useMemo(() => {
    if (summary.overall_health_status === "HEALTHY") return 5;
    let score = 0;
    for (const f of findings) {
      if (f.severity === "CRITICAL") score += 35;
      else if (f.severity === "HIGH") score += 20;
      else if (f.severity === "MEDIUM") score += 10;
      else score += 5;
    }
    return Math.min(98, Math.max(15, score));
  }, [summary, findings]);

  return (
    <div className="space-y-6">
      <style
        dangerouslySetInnerHTML={{
          __html: `
            @media print {
              @page {
                margin: 0;
                size: auto;
              }
              header, footer, nav, aside, .no-print, [data-no-print], .print\\:hidden {
                display: none !important;
                visibility: hidden !important;
                height: 0 !important;
                width: 0 !important;
                overflow: hidden !important;
                position: absolute !important;
                top: -9999px !important;
                left: -9999px !important;
                opacity: 0 !important;
                pointer-events: none !important;
              }
              body {
                background: #ffffff !important;
                color: #0f172a !important;
                padding: 1.2cm !important;
              }
              * {
                position: static !important;
                box-shadow: none !important;
                backdrop-filter: none !important;
                -webkit-backdrop-filter: none !important;
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
              }
              /* Critical: Prevent cards and boxes from splitting across pages */
              .print-avoid-break,
              .break-inside-avoid,
              div[class*="rounded-"],
              div[class*="border"],
              table,
              tr,
              tbody {
                break-inside: avoid !important;
                page-break-inside: avoid !important;
              }
              h1, h2, h3, h4, h5, h6 {
                break-after: avoid !important;
                page-break-after: avoid !important;
              }
              .h-full,
              div[class*="items-stretch"] > * {
                height: auto !important;
                min-height: 0 !important;
              }
            }
          `,
        }}
      />
      {/* Action Toolbar (hidden on print) */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-raised border border-rule rounded-card print:hidden no-print">
        <div className="flex items-center gap-2 text-xs text-ink-2">
          <FileText size={15} className="text-brand" />
          <span>Forensic Chain of Custody & Audit Document</span>
        </div>

        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={handlePrint}>
            <Printer size={13} />
            <span>Print / Save as PDF</span>
          </Button>
        </div>
      </div>

      {/* Official Forensic Report Whitepaper Container */}
      <div className="bg-raised border border-rule rounded-card p-8 lg:p-12 shadow-sm space-y-8 print:border-none print:p-0 print:shadow-none">
        {/* Document Header */}
        <div className="border-b-2 border-ink pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-brand font-bold tracking-wider uppercase">
              <span>Automated Network Forensic Audit</span>
              <span>•</span>
              <span>Platform Engine v1.0.0</span>
            </div>
            <h1 className="text-2xl lg:text-3xl font-extrabold text-ink mt-1 font-serif">
              Technical Telemetry & Security Incident Report
            </h1>
            <p className="text-xs text-ink-2 mt-1">
              Automated Packet Capture Diagnostic & Cyber Incident Triage
            </p>
          </div>

          <div className="text-right text-xs font-mono space-y-1">
            <div>
              <span className="text-ink-2">REPORT ID: </span>
              <span className="font-bold text-ink">PKT-AUDIT-{stats.capture_md5?.slice(0, 8).toUpperCase() || "20261101"}</span>
            </div>
            <div>
              <span className="text-ink-2">TIMESTAMP: </span>
              <span className="text-ink">{new Date().toISOString()}</span>
            </div>
            <div>
              <span className="text-ink-2">STATUS: </span>
              <span className={cn(
                "font-bold",
                summary.overall_health_status === "CRITICAL" ? "text-red-600" : summary.overall_health_status === "WARNING" ? "text-amber-600" : "text-green-600"
              )}>
                {summary.overall_health_status}
              </span>
            </div>
          </div>
        </div>

        {/* Chain of Custody & Cryptographic Hash */}
        <div
          className="p-4 bg-sunk rounded-[10px] border border-rule text-xs space-y-2 print-avoid-break"
          style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
        >
          <div className="font-bold text-ink uppercase tracking-wider text-[11px] flex items-center gap-1.5">
            <Hash size={13} className="text-brand" />
            <span>Chain of Custody & Evidence Checksums</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
            <div>
              <span className="text-ink-2">Target Capture: </span>
              <span className="text-ink font-semibold">{captureName}</span>
            </div>
            <div>
              <span className="text-ink-2">Packets Analyzed: </span>
              <span className="text-ink font-semibold">{summary.total_packets_analyzed.toLocaleString()} frames</span>
            </div>
            <div className="truncate">
              <span className="text-ink-2">SHA-256 Checksum: </span>
              <span className="text-ink font-bold">{stats.capture_sha256 || "N/A"}</span>
            </div>
            <div>
              <span className="text-ink-2">MD5 Digest: </span>
              <span className="text-ink font-bold">{stats.capture_md5 || "N/A"}</span>
            </div>
          </div>
        </div>

        {/* Executive Verdict & Risk Score Section (Symmetric 50/50 Layout) */}
        <div
          className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch print-avoid-break"
          style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
        >
          {/* Radial Score Gauge (Left Equal Box) */}
          <div
            className="p-8 bg-canvas border border-rule rounded-2xl flex flex-col items-center justify-between text-center h-full shadow-xs print-avoid-break"
            style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
          >
            <div className="text-xs uppercase font-bold text-ink-3 tracking-wider">
              Composite Threat Risk Score
            </div>

            {/* Circular Gauge SVG */}
            <div className="relative w-36 h-36 my-4 flex items-center justify-center">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-rule-soft"
                  strokeWidth="3"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={cn(
                    riskScore > 65
                      ? "text-red-600"
                      : riskScore > 30
                      ? "text-amber-500"
                      : "text-green-600"
                  )}
                  strokeDasharray={`${riskScore}, 100`}
                  strokeWidth="3.2"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center">
                <span className="text-4xl font-extrabold font-mono text-ink">
                  {riskScore}
                </span>
                <span className="text-[10px] font-mono text-ink-3 uppercase font-bold">OUT OF 100</span>
              </div>
            </div>

            <Chip
              tone={
                summary.overall_health_status === "CRITICAL"
                  ? "flag"
                  : summary.overall_health_status === "WARNING"
                  ? "warn"
                  : "ok"
              }
            >
              {summary.overall_health_status} STATUS
            </Chip>
          </div>

          {/* Classification & Plain Summary (Right Equal Box) */}
          <div
            className="p-8 bg-canvas border border-rule rounded-2xl flex flex-col justify-between h-full space-y-4 shadow-xs print-avoid-break"
            style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
          >
            <div>
              <div className="text-xs font-mono uppercase text-ink-3 font-bold tracking-wider">
                Primary Diagnostic Classification
              </div>
              <h2 className="text-2xl font-bold text-ink mt-1">
                {summary.primary_classification.replace("_", " ")}
              </h2>
            </div>

            <div className="p-5 bg-sunk/60 rounded-xl border border-rule text-base leading-relaxed text-ink">
              <span className="font-bold block text-xs uppercase tracking-wider text-ink-3 mb-1">
                Executive Plain-Language Summary:
              </span>
              {summary.executive_summary}
            </div>

            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="p-3.5 bg-raised border border-rule rounded-xl">
                <div className="text-xs uppercase font-bold text-ink-3">Attacks</div>
                <div className="text-xl font-bold font-mono text-red-600 mt-1">{stats.attack_count}</div>
              </div>
              <div className="p-3.5 bg-raised border border-rule rounded-xl">
                <div className="text-xs uppercase font-bold text-ink-3">Faults</div>
                <div className="text-xl font-bold font-mono text-amber-600 mt-1">{stats.fault_count}</div>
              </div>
              <div className="p-3.5 bg-raised border border-rule rounded-xl">
                <div className="text-xs uppercase font-bold text-ink-3">Packet Loss</div>
                <div className="text-xl font-bold font-mono text-ink mt-1">{stats.packet_loss_percentage}%</div>
              </div>
            </div>
          </div>
        </div>

        {/* MITRE ATT&CK Matrix Alignment */}
        <div className="space-y-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-ink border-b border-rule pb-2">
            MITRE ATT&CK Enterprise Framework Alignment
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border border-rule rounded-[8px]">
              <thead className="bg-sunk text-ink-2 uppercase font-mono text-[10px]">
                <tr>
                  <th className="p-3">Technique ID</th>
                  <th className="p-3">Technique Name</th>
                  <th className="p-3">ATT&CK Tactic</th>
                  <th className="p-3">Mapped Finding</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule">
                {findings
                  .filter(f => f.mitre_technique)
                  .map(f => (
                    <tr
                      key={f.id}
                      className="hover:bg-raised-hover print-avoid-break"
                      style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
                    >
                      <td className="p-3 font-mono font-bold text-brand">
                        <a
                          href={f.mitre_technique?.url}
                          target="_blank"
                          rel="noreferrer"
                          className="hover:underline flex items-center gap-1"
                        >
                          {f.mitre_technique?.id}
                          <ExternalLink size={10} className="print:hidden" />
                        </a>
                      </td>
                      <td className="p-3 font-medium text-ink">{f.mitre_technique?.name}</td>
                      <td className="p-3 text-ink-2 font-mono">{f.mitre_technique?.tactic}</td>
                      <td className="p-3 text-ink font-semibold">{f.id} - {f.issue_title}</td>
                    </tr>
                  ))}
                {findings.filter(f => f.mitre_technique).length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-4 text-center text-ink-2 text-xs">
                      No malicious cyber attack techniques identified in this capture.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Detailed Findings Table */}
        <div className="space-y-4">
          <h3 className="text-sm font-bold uppercase tracking-wider text-ink border-b border-rule pb-2">
            Detailed Diagnostic Findings & Evidence Breakdown ({findings.length})
          </h3>

          <div className="space-y-6">
            {findings.map((f, i) => (
              <div
                key={f.id}
                className="p-5 bg-canvas border border-rule rounded-[10px] space-y-4 print:border-black/20 print-avoid-break shadow-2xs"
                style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-rule-soft pb-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sm text-ink">{f.id}</span>
                    <h4 className="font-bold text-ink text-base">{f.issue_title}</h4>
                  </div>
                  <div className="flex items-center gap-2">
                    <Chip tone={f.category === "ATTACK" ? "flag" : "warn"}>
                      {f.category}
                    </Chip>
                    <Chip tone={f.severity === "CRITICAL" ? "flag" : f.severity === "HIGH" ? "warn" : "muted"}>
                      {f.severity}
                    </Chip>
                    <span className="text-xs font-mono text-ink-2">Confidence: {f.confidence_score}%</span>
                  </div>
                </div>

                {/* Plain language explanation */}
                <div className="text-xs leading-relaxed text-ink">
                  <span className="font-bold uppercase text-[10px] text-ink-2 block mb-0.5">
                    Non-Expert Explanation:
                  </span>
                  {f.plain_language_explanation}
                </div>

                {/* Root cause */}
                <div className="text-xs leading-relaxed text-ink bg-sunk p-3 rounded-[8px] border border-rule-soft">
                  <span className="font-bold uppercase text-[10px] text-ink-2 block mb-0.5">
                    Technical Root Cause Analysis:
                  </span>
                  {f.technical_details.root_cause}
                </div>

                {/* Evidence Packets */}
                <div>
                  <span className="font-bold uppercase text-[10px] text-ink-2 block mb-1">
                    Telemetry Evidence Citations:
                  </span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5 font-mono text-[11px] text-ink">
                    {f.technical_details.evidence_packets.map((ev, idx) => (
                      <div
                        key={idx}
                        className="p-1.5 px-2 bg-raised rounded border border-rule-soft flex items-center gap-2"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-brand" />
                        <span className="truncate">{ev}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Dual Remediation Plan */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-2">
                  <div
                    className="p-3 bg-red-500/5 border border-red-500/20 rounded-[8px] print-avoid-break"
                    style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
                  >
                    <span className="font-bold uppercase text-[10px] text-red-600 block">
                      Immediate Action:
                    </span>
                    <p className="text-ink mt-0.5 text-[11px]">
                      {f.recommended_remediation.immediate_action}
                    </p>
                  </div>
                  <div
                    className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-[8px] print-avoid-break"
                    style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
                  >
                    <span className="font-bold uppercase text-[10px] text-blue-600 block">
                      Long-Term Fix:
                    </span>
                    <p className="text-ink mt-0.5 text-[11px]">
                      {f.recommended_remediation.long_term_fix}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Forensic Sign-off Footer */}
        <div
          className="border-t border-rule pt-6 flex flex-wrap items-center justify-between text-xs text-ink-2 print-avoid-break"
          style={{ breakInside: "avoid", pageBreakInside: "avoid" }}
        >
          <div>
            <span>Engine: </span>
            <span className="font-mono text-ink">PacketFlow Automated Diagnostic Core v1.0.0</span>
          </div>
          <div>
            <span>Generated for Hackathon Evaluation • IIITDM Kancheepuram</span>
          </div>
        </div>
      </div>
    </div>
  );
}
