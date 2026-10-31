"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Layers } from "lucide-react";
import { PacketInspector } from "@/components/PacketInspector";
import { useCapture } from "@/lib/context/CaptureContext";

function PacketsContent() {
  const searchParams = useSearchParams();
  const frameParam = searchParams.get("frame");
  const initialFrame = frameParam ? parseInt(frameParam, 10) : null;

  const { analysisResult } = useCapture();
  const packets = analysisResult.packets;

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
            <span className="text-ink font-semibold">Deep Packet Inspection</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">
            Deep Packet Inspection &amp; Protocol Stream
          </h1>
          <p className="text-xs sm:text-sm text-ink-2 mt-0.5">
            Real-time frame decoding, protocol header breakdown (Ethernet II, IPv4/v6, TCP/UDP/DNS/DHCP), and safe hex payload viewer.
          </p>
        </div>
      </div>

      {/* Interactive Packet Inspector */}
      <PacketInspector
        packets={packets}
        selectedPacketFrame={initialFrame}
      />
    </main>
  );
}

export default function PacketsPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-ink-2">Loading packet stream...</div>}>
      <PacketsContent />
    </Suspense>
  );
}
