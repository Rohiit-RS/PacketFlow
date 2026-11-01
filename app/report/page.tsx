"use client";

import React from "react";
import { useCapture } from "@/lib/context/CaptureContext";
import { ForensicReport } from "@/components/ForensicReport";
import { FileText, ArrowLeft, ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function ReportPage() {
  const { analysisResult, currentCaptureName } = useCapture();
  const { report } = analysisResult;

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-6 print:p-0 print:m-0 print:max-w-none print:space-y-0">
      {/* Top Breadcrumb Navigation & Title (hidden on print) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-rule print:hidden no-print">
        <div>
          <div className="flex items-center gap-2.5 text-sm text-ink-3 mb-1.5">
            <Link
              href="/"
              className="hover:text-brand hover:underline inline-flex items-center gap-1 font-medium"
            >
              <ArrowLeft size={14} />
              <span>Dashboard</span>
            </Link>
            <span>/</span>
            <span className="text-ink font-semibold">Executive Forensic Audit Dossier</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-ink">
            Official Forensic Dossier &amp; Chain of Custody
          </h1>
          <p className="text-sm sm:text-base text-ink-2 mt-1">
            Print and PDF-ready technical audit report with SHA-256 evidence integrity hashes and MITRE ATT&amp;CK mappings.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className="px-3 py-1.5 rounded-full text-xs font-mono font-bold bg-sunk text-ink-2 border border-rule">
            {currentCaptureName}
          </span>
          <Link
            href="/findings"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full bg-raised hover:bg-raised-hover text-ink text-xs font-semibold border border-rule transition-colors"
          >
            <ShieldAlert size={13} className="text-flag" />
            <span>View {report.findings.length} Findings</span>
          </Link>
        </div>
      </div>

      {/* Forensic Report Component */}
      <ForensicReport
        analysisResult={analysisResult}
        captureName={currentCaptureName}
      />
    </main>
  );
}
