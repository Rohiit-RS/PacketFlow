"use client";

import React from "react";
import { useCapture } from "@/lib/context/CaptureContext";
import { NetworkTopology } from "@/components/NetworkTopology";
import { Network, ArrowLeft, ShieldAlert } from "lucide-react";
import Link from "next/link";

export default function TopologyPage() {
  const { analysisResult, currentCaptureName } = useCapture();
  const { packets, flows, report } = analysisResult;

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-6">
      {/* Top Breadcrumb Navigation & Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-rule">
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
            <span className="text-ink font-semibold">Network Threat Topology</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-ink">
            Interactive Network Threat &amp; Host Topology
          </h1>
          <p className="text-sm sm:text-base text-ink-2 mt-1">
            Visual node-link communication matrix reconstructing live packet conversations across internal hosts, gateways, and external endpoints.
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

      {/* Network Topology Graph */}
      <NetworkTopology
        packets={packets}
        flows={flows}
        findings={report.findings}
      />
    </main>
  );
}
