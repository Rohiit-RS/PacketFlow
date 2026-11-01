"use client";

import { useState, useRef, ChangeEvent, DragEvent } from "react";
import {
  UploadCloud,
  FileCode,
  Sparkles,
  ClipboardPaste,
  CheckCircle2,
  Layers,
  Download,
} from "lucide-react";
import { Button, Chip, Panel, Swatch, cn } from "./ui";
import { SAMPLE_SCENARIOS } from "@/lib/samples/sampleData";
import { useCapture } from "@/lib/context/CaptureContext";
import { synthesizePcapBinary } from "@/lib/engine/pcapWriter";
import { toast } from "sonner";

export function IngestionZone() {
  const {
    currentCaptureName,
    analysisResult,
    isProcessing,
    loadScenario,
    uploadFile,
    pasteJson,
  } = useCapture();

  const [isDragging, setIsDragging] = useState(false);
  const [pasteModalOpen, setPasteModalOpen] = useState(false);
  const [pasteContent, setPasteContent] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      try {
        await uploadFile(file);
      } catch (err) {
        toast.error(`Failed to parse file: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  };

  const handleFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      try {
        await uploadFile(file);
      } catch (err) {
        toast.error(`Failed to parse file: ${err instanceof Error ? err.message : String(err)}`);
      }
      e.target.value = "";
    }
  };

  const handlePasteSubmit = () => {
    if (!pasteContent.trim()) {
      toast.error("Please paste JSON packet telemetry first.");
      return;
    }
    try {
      pasteJson(pasteContent);
      setPasteModalOpen(false);
      setPasteContent("");
    } catch (err) {
      toast.error(`Parsing error: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDownloadPcap = () => {
    try {
      const pcapBytes = synthesizePcapBinary(analysisResult.packets);
      const blob = new Blob([pcapBytes as BlobPart], { type: "application/vnd.tcpdump.pcap" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${currentCaptureName.replace(/\.[^/.]+$/, "")}.pcap`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("Downloaded Wireshark-compatible .pcap capture!");
    } catch (err) {
      toast.error("Failed to generate .pcap file.");
    }
  };

  const handleDownloadJson = () => {
    try {
      const jsonStr = JSON.stringify(analysisResult.packets, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${currentCaptureName.replace(/\.[^/.]+$/, "")}_telemetry.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.success("Downloaded JSON telemetry capture file!");
    } catch (err) {
      toast.error("Failed to generate JSON file.");
    }
  };

  return (
    <div className="space-y-6">
      {/* Symmetric Ingestion Area (2 equal boxes) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
        {/* Left: Drag and Drop Upload Box */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={cn(
            "border border-dashed rounded-2xl p-6 flex flex-col justify-between transition-all cursor-pointer bg-raised h-full shadow-xs",
            isDragging
              ? "border-brand bg-brand-soft/60"
              : "border-rule hover:border-brand hover:bg-sunk/40"
          )}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap,.json"
            onChange={handleFileChange}
            className="hidden"
          />

          <div className="flex items-start gap-4 mb-4">
            <div className="h-12 w-12 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
              <UploadCloud size={24} />
            </div>
            <div>
              <h3 className="text-base font-bold text-ink">
                Ingest Packet Capture
              </h3>
              <p className="text-sm text-ink-2 mt-1 leading-relaxed">
                Drag &amp; drop any <span className="font-mono text-brand font-semibold">.pcap</span>,{" "}
                <span className="font-mono text-brand font-semibold">.pcapng</span>, or JSON telemetry file.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-between pt-4 border-t border-rule-soft text-xs text-ink-3">
            <span>Client-side safe binary parser</span>
            <Button variant="secondary" size="sm" className="pointer-events-none">
              Browse File
            </Button>
          </div>
        </div>

        {/* Right: Active Capture & Telemetry Options */}
        <Panel className="p-6 flex flex-col justify-between h-full border border-rule shadow-xs">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-ink-3 uppercase tracking-wider">
                Telemetry State
              </span>
              <Chip tone="ok">
                <CheckCircle2 size={13} className="text-ok" />
                {isProcessing ? "Processing Telemetry..." : "Engine Active"}
              </Chip>
            </div>

            <h3 className="text-lg font-bold text-ink truncate mb-1">
              {currentCaptureName}
            </h3>
            <p className="text-sm font-medium text-ink-2 font-mono">
              {analysisResult.stats.total_packets.toLocaleString()} frames ingested • Bounds-checked
            </p>
          </div>

          <div className="pt-4 border-t border-rule flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleDownloadPcap}
                title="Download this capture as a binary .pcap file to open in Wireshark"
              >
                <Download size={13} />
                <span>Export .pcap</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleDownloadJson}
                title="Download this capture as JSON telemetry"
              >
                <FileCode size={13} />
                <span>Export JSON</span>
              </Button>
            </div>

            <Button
              variant="secondary"
              size="sm"
              onClick={() => setPasteModalOpen(true)}
            >
              <ClipboardPaste size={14} className="text-brand" />
              <span>Paste JSON Logs</span>
            </Button>
          </div>
        </Panel>
      </div>

      {/* Symmetric 1-Click Evaluation Presets */}
      <Panel className="p-6 bg-raised border border-rule shadow-xs">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-4">
          <div className="flex items-center gap-2">
            <Sparkles size={18} className="text-brand" />
            <span className="text-sm uppercase tracking-wider font-bold text-ink">
              Evaluation Scenarios (1-Click Test Captures)
            </span>
          </div>
          <span className="text-sm text-ink-3">
            Click any scenario to instantly run diagnosis
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 items-stretch">
          {SAMPLE_SCENARIOS.slice(0, 4).map((scenario) => {
            const isSelected = currentCaptureName === scenario.name;
            const swatchColor =
              scenario.category === "ATTACK"
                ? "var(--color-flag)"
                : scenario.category === "FAULT"
                ? "var(--color-warn)"
                : scenario.category === "MIXED"
                ? "var(--color-pend)"
                : "var(--color-ok)";

            return (
              <button
                key={scenario.id}
                type="button"
                onClick={() => loadScenario(scenario)}
                className={cn(
                  "flex flex-col justify-between text-left p-4 rounded-xl border transition-all cursor-pointer h-full",
                  isSelected
                    ? "border-brand bg-brand-soft/70 shadow-xs"
                    : "border-rule bg-raised hover:border-brand/40 hover:bg-sunk/50"
                )}
              >
                <div className="flex items-center justify-between w-full mb-2">
                  <Swatch color={swatchColor} className="w-3 h-3 rounded" />
                  <span className="text-xs text-ink-3 font-mono font-medium">
                    {scenario.packetCount} pkts
                  </span>
                </div>
                <div>
                  <span className="font-bold text-base text-ink block leading-snug">
                    {scenario.name}
                  </span>
                  <span className="text-xs text-ink-2 block mt-1">
                    {scenario.badge}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </Panel>

      {/* Paste Telemetry Modal */}
      {pasteModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
          <div className="bg-raised border border-rule rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <FileCode size={18} className="text-brand" />
                <h3 className="font-bold text-lg text-ink">Paste JSON Packet Telemetry</h3>
              </div>
              <button
                onClick={() => setPasteModalOpen(false)}
                className="text-ink-3 hover:text-ink text-sm font-semibold p-1"
              >
                Cancel
              </button>
            </div>

            <p className="text-sm text-ink-2">
              Paste array of packet objects or Wireshark JSON telemetry export:
            </p>

            <textarea
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              placeholder='[ { "frame_number": 1, "protocol": "TCP", "source_ip": "192.168.1.10", "destination_ip": "192.168.1.1" } ]'
              rows={10}
              className="w-full p-3 font-mono text-sm bg-sunk rounded-xl border border-rule focus:outline-none focus:border-brand text-ink"
            />

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="secondary" size="md" onClick={() => setPasteModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" size="md" onClick={handlePasteSubmit}>
                Analyze Telemetry
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
