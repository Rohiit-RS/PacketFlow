"use client";

import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { FlowMatrix } from "@/components/FlowMatrix";
import { useCapture } from "@/lib/context/CaptureContext";

export default function FlowsPage() {
  const { analysisResult } = useCapture();
  const flows = analysisResult.flows;

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-6">
      {/* Top Breadcrumb Navigation */}
      <div className="flex items-center justify-between gap-4 pb-2 border-b border-rule">
        <div>
          <div className="flex items-center gap-2 text-xs text-ink-3 mb-1">
            <Link href="/" className="hover:text-brand hover:underline inline-flex items-center gap-1">
              <ArrowLeft size={12} />
              <span>Overview</span>
            </Link>
            <span>/</span>
            <span className="text-ink font-semibold">Flow Matrix</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">
            Conversation Flow Matrix
          </h1>
          <p className="text-xs sm:text-sm text-ink-2 mt-0.5">
            Bidirectional endpoint conversations reconstructed across TCP sequence space with RTT latency and packet loss tracking.
          </p>
        </div>
      </div>

      {/* Interactive Flow Matrix Component */}
      <FlowMatrix flows={flows} />
    </main>
  );
}
