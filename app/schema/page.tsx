"use client";

import Link from "next/link";
import { ArrowLeft, Terminal, Copy } from "lucide-react";
import { SchemaViewer } from "@/components/SchemaViewer";
import { Panel, SectionTitle, Button } from "@/components/ui";
import { useCapture } from "@/lib/context/CaptureContext";
import { toast } from "sonner";

export default function SchemaPage() {
  const { analysisResult } = useCapture();

  const curlCommand = `curl -X POST "https://your-domain.vercel.app/api/analyze" \\
  --data-binary "@sample-captures/1_arp_spoofing_mitm.pcap" \\
  -H "Content-Type: application/octet-stream"`;

  const copyCurl = () => {
    try {
      navigator.clipboard.writeText(curlCommand);
      toast.success("cURL command copied to clipboard!");
    } catch {
      toast.error("Failed to copy.");
    }
  };

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
            <span className="text-ink font-semibold">JSON Schema &amp; REST API</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">
            Strict Output Schema &amp; REST API
          </h1>
          <p className="text-xs sm:text-sm text-ink-2 mt-0.5">
            Strict JSON specification schema output produced by the diagnostic engine, fully compatible with automated incident response pipelines.
          </p>
        </div>
      </div>

      {/* Live Schema Viewer */}
      <SchemaViewer report={analysisResult.report} />

      {/* REST API Integration Guide */}
      <Panel className="p-6 space-y-4">
        <div className="flex items-center justify-between">
          <SectionTitle sub="Programmatic PCAP analysis via HTTP POST">
            REST API Endpoint: /api/analyze
          </SectionTitle>
          <Button variant="secondary" size="sm" onClick={copyCurl}>
            <Copy size={13} />
            <span>Copy cURL</span>
          </Button>
        </div>

        <div className="space-y-2 text-xs text-ink-2 leading-relaxed">
          <p>
            You can query the diagnostic engine programmatically by sending raw binary PCAP data, multipart form uploads, or JSON packet arrays to the API route:
          </p>
          <pre className="p-3 bg-sunk rounded-[10px] font-mono text-xs text-ink border border-rule overflow-x-auto">
            {curlCommand}
          </pre>
          <p className="text-[11px] text-ink-3">
            Supports both raw octet-stream `.pcap` files and JSON arrays. Returns HTTP 200 with the exact JSON schema above.
          </p>
        </div>
      </Panel>
    </main>
  );
}
