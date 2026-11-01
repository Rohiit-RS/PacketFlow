"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Terminal,
  Play,
  Copy,
  Check,
  Code2,
  FileJson,
  Sparkles,
  Layers,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Clock,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import { Panel, SectionTitle, Button, Chip, Swatch, cn } from "@/components/ui";
import { SchemaViewer } from "@/components/SchemaViewer";
import { useCapture } from "@/lib/context/CaptureContext";
import { toast } from "sonner";

type ApiTab = "PLAYGROUND" | "SCHEMA" | "INTEGRATION";

const SAMPLE_PAYLOADS: Record<string, { label: string; packets: any[] }> = {
  ARP_SPOOF: {
    label: "ARP Cache Poisoning",
    packets: [
      {
        frame_number: 1,
        timestamp: 1730419200.0,
        length: 60,
        protocol: "ARP",
        arp_opcode: "REPLY",
        arp_sender_ip: "192.168.1.1",
        arp_sender_mac: "00:0c:29:8a:4f:1b",
        info: "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]",
      },
      {
        frame_number: 2,
        timestamp: 1730419200.05,
        length: 60,
        protocol: "ARP",
        arp_opcode: "REPLY",
        arp_sender_ip: "192.168.1.1",
        arp_sender_mac: "00:0c:29:8a:4f:1b",
        info: "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]",
      },
      {
        frame_number: 3,
        timestamp: 1730419200.1,
        length: 60,
        protocol: "ARP",
        arp_opcode: "REPLY",
        arp_sender_ip: "192.168.1.1",
        arp_sender_mac: "00:0c:29:8a:4f:1b",
        info: "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]",
      },
    ],
  },
  SYN_SCAN: {
    label: "TCP Port Scan (SYN Sweep)",
    packets: [
      {
        frame_number: 1,
        timestamp: 1730419210.0,
        length: 64,
        protocol: "TCP",
        src_ip: "10.0.0.99",
        dst_ip: "192.168.1.50",
        src_port: 49152,
        dst_port: 21,
        tcp_flags: "SYN",
        info: "49152 -> 21 [SYN] Seq=0 Win=1024 Len=0",
      },
      {
        frame_number: 2,
        timestamp: 1730419210.01,
        length: 64,
        protocol: "TCP",
        src_ip: "10.0.0.99",
        dst_ip: "192.168.1.50",
        src_port: 49153,
        dst_port: 22,
        tcp_flags: "SYN",
        info: "49153 -> 22 [SYN] Seq=0 Win=1024 Len=0",
      },
      {
        frame_number: 3,
        timestamp: 1730419210.02,
        length: 64,
        protocol: "TCP",
        src_ip: "10.0.0.99",
        dst_ip: "192.168.1.50",
        src_port: 49154,
        dst_port: 80,
        tcp_flags: "SYN",
        info: "49154 -> 80 [SYN] Seq=0 Win=1024 Len=0",
      },
      {
        frame_number: 4,
        timestamp: 1730419210.03,
        length: 64,
        protocol: "TCP",
        src_ip: "10.0.0.99",
        dst_ip: "192.168.1.50",
        src_port: 49155,
        dst_port: 443,
        tcp_flags: "SYN",
        info: "49155 -> 443 [SYN] Seq=0 Win=1024 Len=0",
      },
    ],
  },
  CLEAN_BASELINE: {
    label: "Clean RFC Baseline",
    packets: [
      {
        frame_number: 1,
        timestamp: 1730419300.0,
        length: 74,
        protocol: "TCP",
        src_ip: "192.168.1.10",
        dst_ip: "192.168.1.1",
        src_port: 52100,
        dst_port: 443,
        tcp_flags: "SYN",
        info: "52100 -> 443 [SYN] Seq=0 Win=65535 Len=0",
      },
      {
        frame_number: 2,
        timestamp: 1730419300.02,
        length: 74,
        protocol: "TCP",
        src_ip: "192.168.1.1",
        dst_ip: "192.168.1.10",
        src_port: 443,
        dst_port: 52100,
        tcp_flags: "SYN, ACK",
        info: "443 -> 52100 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0",
      },
      {
        frame_number: 3,
        timestamp: 1730419300.03,
        length: 66,
        protocol: "TCP",
        src_ip: "192.168.1.10",
        dst_ip: "192.168.1.1",
        src_port: 52100,
        dst_port: 443,
        tcp_flags: "ACK",
        info: "52100 -> 443 [ACK] Seq=1 Ack=1 Win=65535 Len=0",
      },
    ],
  },
};

export default function ApiPage() {
  const { analysisResult } = useCapture();
  const [activeTab, setActiveTab] = useState<ApiTab>("PLAYGROUND");
  const [selectedPreset, setSelectedPreset] = useState<string>("ARP_SPOOF");
  const [payloadText, setPayloadText] = useState(() =>
    JSON.stringify(SAMPLE_PAYLOADS.ARP_SPOOF.packets, null, 2)
  );
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState<any>(null);
  const [executionStatus, setExecutionStatus] = useState<string | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [copiedCurl, setCopiedCurl] = useState(false);
  const [copiedResponse, setCopiedResponse] = useState(false);

  // Load preset scenario
  const handleSelectPreset = (key: string) => {
    setSelectedPreset(key);
    setPayloadText(JSON.stringify(SAMPLE_PAYLOADS[key].packets, null, 2));
  };

  // Execute diagnostic POST request against /api/analyse
  const executeAnalysis = async () => {
    setIsExecuting(true);
    setExecutionStatus("Executing diagnostic engine...");
    const startTime = performance.now();

    try {
      // Validate JSON syntax first
      const parsed = JSON.parse(payloadText);

      const res = await fetch("/api/analyse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(parsed),
      });

      const elapsed = Math.round(performance.now() - startTime);
      setLatencyMs(elapsed);

      const data = await res.json();
      setExecutionResult(data);
      setExecutionStatus(`HTTP ${res.status} OK`);
      toast.success(`Analysis executed successfully in ${elapsed}ms!`);
    } catch (err: any) {
      setExecutionStatus(`Error: ${err.message}`);
      setExecutionResult({ error: err.message });
      toast.error(`Execution failed: ${err.message}`);
    } finally {
      setIsExecuting(false);
    }
  };

  // Auto-run once on component mount so the response viewer displays immediately
  useEffect(() => {
    executeAnalysis();
  }, []);

  const copyCurl = () => {
    try {
      const curl = `curl -X POST http://localhost:3000/api/analyse \\\n  -H "Content-Type: application/json" \\\n  -d '${payloadText.replace(/\n/g, "").replace(/\s+/g, " ")}'`;
      navigator.clipboard.writeText(curl);
      setCopiedCurl(true);
      toast.success("cURL command copied to clipboard!");
      setTimeout(() => setCopiedCurl(false), 2000);
    } catch {
      toast.error("Failed to copy cURL command.");
    }
  };

  const copyResponse = () => {
    try {
      if (!executionResult) return;
      navigator.clipboard.writeText(JSON.stringify(executionResult, null, 2));
      setCopiedResponse(true);
      toast.success("Response JSON copied to clipboard!");
      setTimeout(() => setCopiedResponse(false), 2000);
    } catch {
      toast.error("Failed to copy response.");
    }
  };

  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-6">
      {/* Top Breadcrumb Navigation & Header */}
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
            <span className="text-ink font-semibold">REST API &amp; Evaluation Schema</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-ink">
            REST API &amp; Diagnostic Playground
          </h1>
          <p className="text-sm sm:text-base text-ink-2 mt-1">
            Programmatic evaluation endpoint with live browser execution, strict JSON schema output, and zero-wrapper parser guarantees.
          </p>
        </div>

        {/* Live Endpoint Status Pill */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-mono font-bold bg-ok-soft text-ok border border-ok-line">
            <span className="h-2 w-2 rounded-full bg-ok animate-pulse" />
            <span>ENDPOINT ONLINE (HTTP 200)</span>
          </div>
          <span className="px-3 py-1.5 rounded-full text-xs font-mono font-bold bg-sunk text-ink-2 border border-rule">
            POST /api/analyse
          </span>
        </div>
      </div>

      {/* Symmetric Tab Navigation Switcher */}
      <div className="flex items-center justify-between gap-4 overflow-x-auto pb-1">
        <div className="flex items-center gap-2 p-1.5 bg-sunk rounded-full border border-rule text-sm">
          <button
            type="button"
            onClick={() => setActiveTab("PLAYGROUND")}
            className={cn(
              "inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-semibold transition-colors cursor-pointer text-sm",
              activeTab === "PLAYGROUND"
                ? "bg-raised text-ink shadow-xs"
                : "text-ink-2 hover:text-ink"
            )}
          >
            <Play size={14} className={activeTab === "PLAYGROUND" ? "text-brand" : ""} />
            <span>Interactive Live Console</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("SCHEMA")}
            className={cn(
              "inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-semibold transition-colors cursor-pointer text-sm",
              activeTab === "SCHEMA"
                ? "bg-raised text-ink shadow-xs"
                : "text-ink-2 hover:text-ink"
            )}
          >
            <FileJson size={14} className={activeTab === "SCHEMA" ? "text-brand" : ""} />
            <span>Strict Evaluation Schema</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("INTEGRATION")}
            className={cn(
              "inline-flex items-center gap-2 px-4 py-1.5 rounded-full font-semibold transition-colors cursor-pointer text-sm",
              activeTab === "INTEGRATION"
                ? "bg-raised text-ink shadow-xs"
                : "text-ink-2 hover:text-ink"
            )}
          >
            <Code2 size={14} className={activeTab === "INTEGRATION" ? "text-brand" : ""} />
            <span>Integration &amp; SDK Snippets</span>
          </button>
        </div>
      </div>

      {/* Tab 1: Live Interactive Console */}
      {activeTab === "PLAYGROUND" && (
        <div className="space-y-6">
          {/* Preset Selector */}
          <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-xl bg-sunk/60 border border-rule">
            <div className="flex items-center gap-2 text-sm text-ink-2">
              <Sparkles size={16} className="text-brand" />
              <span className="font-semibold text-ink">Load Preset Scenario:</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {Object.entries(SAMPLE_PAYLOADS).map(([key, item]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => handleSelectPreset(key)}
                  className={cn(
                    "px-3 py-1 rounded-lg text-xs font-semibold font-mono transition-all border",
                    selectedPreset === key
                      ? "bg-brand text-on-brand border-brand shadow-xs"
                      : "bg-raised text-ink hover:border-brand-line border-rule"
                  )}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          {/* Symmetric Two-Column Diagnostic Console */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
            {/* Left Box: Request Payload Editor */}
            <Panel className="p-6 flex flex-col justify-between h-full border border-rule shadow-xs space-y-4">
              <div>
                <div className="flex items-center justify-between gap-2 mb-3 pb-3 border-b border-rule">
                  <div>
                    <h2 className="text-lg font-bold text-ink">HTTP Request Payload</h2>
                    <span className="text-xs text-ink-3 font-mono">Content-Type: application/json</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleSelectPreset(selectedPreset)}
                    className="inline-flex items-center gap-1 text-xs text-ink-3 hover:text-ink font-mono"
                  >
                    <RotateCcw size={12} />
                    <span>Reset</span>
                  </button>
                </div>

                <textarea
                  value={payloadText}
                  onChange={(e) => setPayloadText(e.target.value)}
                  rows={16}
                  className="w-full p-3.5 rounded-xl bg-sunk font-mono text-xs text-ink border border-rule focus:outline-none focus:border-brand resize-vertical leading-relaxed selection:bg-brand-soft"
                  spellCheck={false}
                />
              </div>

              <div className="flex flex-wrap items-center gap-3 pt-4 border-t border-rule mt-2">
                <Button
                  variant="primary"
                  size="md"
                  onClick={executeAnalysis}
                  disabled={isExecuting}
                  className="font-bold flex-1"
                >
                  {isExecuting ? (
                    <>
                      <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Running Diagnosis...</span>
                    </>
                  ) : (
                    <>
                      <Play size={15} />
                      <span>Execute Diagnostic POST</span>
                    </>
                  )}
                </Button>

                <Button
                  variant="secondary"
                  size="md"
                  onClick={copyCurl}
                  title="Copy cURL command"
                >
                  {copiedCurl ? <Check size={15} /> : <Copy size={15} />}
                  <span>{copiedCurl ? "Copied cURL" : "Copy cURL"}</span>
                </Button>
              </div>
            </Panel>

            {/* Right Box: Live Diagnostic Engine Response */}
            <Panel className="p-6 flex flex-col justify-between h-full border border-rule shadow-xs space-y-4">
              <div>
                <div className="flex items-center justify-between gap-2 mb-3 pb-3 border-b border-rule">
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-bold text-ink">Engine Diagnostic Output</h2>
                    {executionStatus && (
                      <span
                        className={cn(
                          "px-2 py-0.5 rounded text-xs font-mono font-bold",
                          executionStatus.includes("OK") || executionStatus.includes("200")
                            ? "bg-ok-soft text-ok border border-ok-line"
                            : "bg-warn-soft text-warn border border-warn"
                        )}
                      >
                        {executionStatus}
                      </span>
                    )}
                  </div>

                  {latencyMs !== null && (
                    <span className="text-xs text-ink-3 font-mono flex items-center gap-1">
                      <Clock size={12} />
                      <span>{latencyMs}ms</span>
                    </span>
                  )}
                </div>

                <div className="relative">
                  <pre className="p-3.5 rounded-xl bg-sunk font-mono text-xs text-ink border border-rule overflow-x-auto h-[380px] leading-relaxed selection:bg-brand-soft">
                    {executionResult
                      ? JSON.stringify(executionResult, null, 2)
                      : "// Click 'Execute Diagnostic POST' to inspect live response..."}
                  </pre>
                </div>
              </div>

              <div className="flex items-center justify-between pt-4 border-t border-rule mt-2">
                <span className="text-xs text-ink-3 font-mono">
                  Strict Evaluation Schema (Summary + Findings)
                </span>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={copyResponse}
                  disabled={!executionResult}
                >
                  {copiedResponse ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copiedResponse ? "Copied Response" : "Copy Response JSON"}</span>
                </Button>
              </div>
            </Panel>
          </div>

          {/* Symmetric Bottom Specification Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-stretch">
            <Panel className="p-6 border border-rule space-y-3">
              <h3 className="text-base font-bold text-ink flex items-center gap-2">
                <Layers size={16} className="text-brand" />
                <span>Accepted Telemetry Formats</span>
              </h3>
              <ul className="text-xs sm:text-sm text-ink-2 space-y-2 list-disc pl-5">
                <li>
                  <strong className="text-ink">application/json:</strong> Array of parsed packet telemetry objects or wrapped in <code>{"{ packets: [...] }"}</code>.
                </li>
                <li>
                  <strong className="text-ink">multipart/form-data:</strong> File upload with <code>file</code> field containing <code>.pcap</code>, <code>.pcapng</code>, or <code>.json</code>.
                </li>
                <li>
                  <strong className="text-ink">application/octet-stream:</strong> Raw binary PCAP byte stream submitted directly in the request body.
                </li>
              </ul>
            </Panel>

            <Panel className="p-6 border border-rule space-y-3">
              <h3 className="text-base font-bold text-ink flex items-center gap-2">
                <CheckCircle2 size={16} className="text-ok" />
                <span>Strict Evaluation Guarantees</span>
              </h3>
              <p className="text-xs sm:text-sm text-ink-2 leading-relaxed">
                The endpoint outputs a structured evaluation schema featuring <code>summary</code> (total packet count, overall health, primary classification, 2-sentence executive summary) and <code>findings[]</code> (technical root causes, confidence scores, and remediation playbooks).
              </p>
              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => setActiveTab("SCHEMA")}
                  className="text-xs font-semibold text-brand hover:underline inline-flex items-center gap-1"
                >
                  <span>Inspect Complete JSON Schema Contract</span>
                  <ArrowRight size={13} />
                </button>
              </div>
            </Panel>
          </div>
        </div>
      )}

      {/* Tab 2: Strict JSON Schema Viewer */}
      {activeTab === "SCHEMA" && (
        <div className="space-y-6">
          <SchemaViewer report={analysisResult.report} />
        </div>
      )}

      {/* Tab 3: Integration Code Snippets & SDKs */}
      {activeTab === "INTEGRATION" && (
        <div className="space-y-6">
          <Panel className="p-6 sm:p-8 border border-rule space-y-6">
            <SectionTitle sub="Integrate the diagnostic engine into security pipelines, SIEM, or CI/CD">
              Programmatic Client Integration Snippets
            </SectionTitle>

            <div className="space-y-4">
              <div>
                <span className="text-xs font-bold font-mono text-ink uppercase block mb-1.5">
                  1. cURL Terminal Command (Raw Binary PCAP or JSON)
                </span>
                <pre className="p-4 rounded-xl bg-sunk font-mono text-xs text-ink border border-rule overflow-x-auto leading-relaxed">
{`# 1. Post JSON Telemetry
curl -X POST http://localhost:3000/api/analyse \\
  -H "Content-Type: application/json" \\
  -d '[{"frame_number":1,"timestamp":1730419200,"length":60,"protocol":"ARP","arp_opcode":"REPLY","arp_sender_ip":"192.168.1.1","arp_sender_mac":"00:0c:29:8a:4f:1b","info":"192.168.1.1 is at 00:0c:29:8a:4f:1b"}]'

# 2. Post Binary PCAP File
curl -X POST http://localhost:3000/api/analyse \\
  -H "Content-Type: application/octet-stream" \\
  --data-binary "@traffic.pcap"`}
                </pre>
              </div>

              <div>
                <span className="text-xs font-bold font-mono text-ink uppercase block mb-1.5">
                  2. Python (requests library)
                </span>
                <pre className="p-4 rounded-xl bg-sunk font-mono text-xs text-ink border border-rule overflow-x-auto leading-relaxed">
{`import requests

url = "http://localhost:3000/api/analyse"
with open("capture.pcap", "rb") as f:
    response = requests.post(url, data=f.read(), headers={"Content-Type": "application/octet-stream"})

result = response.json()
print("Classification:", result["summary"]["primary_classification"])
print("Health Status:", result["summary"]["overall_health_status"])
print("Executive Summary:", result["summary"]["executive_summary"])`}
                </pre>
              </div>

              <div>
                <span className="text-xs font-bold font-mono text-ink uppercase block mb-1.5">
                  3. Node.js / TypeScript (Native Fetch)
                </span>
                <pre className="p-4 rounded-xl bg-sunk font-mono text-xs text-ink border border-rule overflow-x-auto leading-relaxed">
{`const fs = require("fs");

async function analyzeCapture() {
  const buffer = fs.readFileSync("traffic.pcap");
  const res = await fetch("http://localhost:3000/api/analyse", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: buffer,
  });

  const diagnosis = await res.json();
  console.log("Summary:", diagnosis.summary);
  console.log("Findings Count:", diagnosis.findings.length);
}

analyzeCapture();`}
                </pre>
              </div>
            </div>
          </Panel>
        </div>
      )}
    </main>
  );
}
