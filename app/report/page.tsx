"use client";

import React from "react";
import { useCapture } from "@/lib/context/CaptureContext";
import { ForensicReport } from "@/components/ForensicReport";
import { FileText, ArrowLeft, ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function ReportPage() {
  const { analysisResult, currentCaptureName } = useCapture();

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation (hidden on print) */}
      <div className="flex items-center justify-between print:hidden">
        <div className="flex items-center gap-2 text-xs font-mono text-ink-2">
          <Link href="/" className="hover:text-ink transition-colors">
            Dashboard
          </Link>
          <span>/</span>
          <span className="text-ink font-semibold">Executive Forensic Audit Report</span>
        </div>

        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-ink-2 hover:text-ink transition-colors"
        >
          <ArrowLeft size={13} />
          <span>Back to Dashboard</span>
        </Link>
      </div>

      {/* Forensic Report Component */}
      <ForensicReport
        analysisResult={analysisResult}
        captureName={currentCaptureName}
      />
    </div>
  );
}
