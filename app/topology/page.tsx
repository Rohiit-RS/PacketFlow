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
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-mono text-ink-2">
          <Link href="/" className="hover:text-ink transition-colors">
            Dashboard
          </Link>
          <span>/</span>
          <span className="text-ink font-semibold">Network Threat Topology</span>
        </div>

        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-ink-2 hover:text-ink transition-colors"
        >
          <ArrowLeft size={13} />
          <span>Back to Dashboard</span>
        </Link>
      </div>

      {/* Header Banner */}
      <div className="bg-raised border border-rule rounded-card p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-10 h-10 rounded-[10px] bg-brand-light text-brand flex items-center justify-center shrink-0">
              <Network size={22} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-ink">
                  Interactive Network Threat & Host Topology
                </h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-sunk border border-rule text-ink-2">
                  {currentCaptureName}
                </span>
              </div>
              <p className="text-xs text-ink-2 mt-1 max-w-2xl">
                Visual node-link communication matrix reconstructing live packet conversations across internal hosts, gateways, and external servers. Hostile connections and reconnaissance probes are highlighted with pulsing threat indicators.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Link
              href="/findings"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] bg-sunk hover:bg-raised-hover text-ink text-xs font-semibold border border-rule transition-colors"
            >
              <ShieldAlert size={14} className="text-brand" />
              <span>View Findings ({report.findings.length})</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Main Interactive Topology Component */}
      <NetworkTopology
        packets={packets}
        flows={flows}
        findings={report.findings}
      />
    </div>
  );
}
