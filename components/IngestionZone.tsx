"use client";

import { useState, useRef, ChangeEvent, DragEvent } from "react";
import {
  UploadCloud,
  FileCode,
  Sparkles,
  ClipboardPaste,
} from "lucide-react";
import { Button, Chip, Panel, Swatch, cn } from "./ui";
import { SAMPLE_SCENARIOS, SampleCaptureScenario } from "@/lib/samples/sampleData";
import { useCapture } from "@/lib/context/CaptureContext";
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

  return (
    <div className="space-y-4">
      {/* 1-Click Evaluation Presets */}
      <Panel className="p-4 bg-raised border border-rule">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2">
            <Sparkles size={16} className="text-brand" />
            <span className="text-xs uppercase tracking-wider font-bold text-ink">
              Evaluation Scenarios (1-Click Test Captures)
            </span>
          </div>
          <span className="text-xs text-ink-3">
            Select any capture scenario to immediately analyze packet telemetry
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2">
          {SAMPLE_SCENARIOS.map((scenario) => {
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
                  "flex flex-col text-left p-3 rounded-[10px] border transition-all text-xs cursor-pointer",
                  isSelected
                    ? "border-brand bg-brand-soft shadow-xs"
                    : "border-rule bg-raised hover:border-rule-strong hover:bg-sunk/60"
                )}
              >
                <div className="flex items-center justify-between w-full mb-1.5">
                  <Swatch color={swatchColor} />
                  <span className="text-[11px] text-ink-3 font-mono">{scenario.packetCount} pkts</span>
                </div>
                <span className="font-semibold text-ink line-clamp-1 leading-snug">{scenario.name}</span>
                <span className="text-[11px] text-ink-3 line-clamp-1 mt-0.5">{scenario.badge}</span>
              </button>
            );
          })}
        </div>
      </Panel>

      {/* Upload Zone & Capture Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Drag and Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={cn(
            "md:col-span-2 border border-dashed rounded-2xl p-5 flex flex-col sm:flex-row items-center gap-4 transition-all cursor-pointer bg-raised",
            isDragging
              ? "border-brand bg-brand-soft"
              : "border-rule-strong hover:border-brand hover:bg-sunk/40"
          )}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap,.json"
            onChange={handleFileChange}
            className="hidden"
          />
          <div className="h-11 w-11 rounded-[10px] bg-brand-soft text-brand flex items-center justify-center shrink-0">
            <UploadCloud size={22} />
          </div>
          <div className="text-center sm:text-left flex-1">
            <p className="text-sm font-semibold text-ink">
              Drop any <span className="font-mono text-brand font-bold">.pcap</span>,{" "}
              <span className="font-mono text-brand font-bold">.pcapng</span>, or JSON capture file here
            </p>
            <p className="text-xs text-ink-2 mt-0.5">
              Client-safe binary parser with memory bounds checking. Payloads are sanitized and never executed.
            </p>
          </div>
          <Button variant="secondary" size="sm" className="shrink-0 pointer-events-none">
            Browse File
          </Button>
        </div>

        {/* Telemetry Status & Paste Action */}
        <Panel className="p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-ink-3 uppercase tracking-wider">Active Capture</span>
            <Chip tone="ok">
              {isProcessing ? "Processing..." : "Engine Ready"}
            </Chip>
          </div>
          <div>
            <p className="font-bold text-sm text-ink line-clamp-1">{currentCaptureName}</p>
            <p className="text-xs text-ink-2 font-mono mt-0.5">
              {analysisResult.stats.total_packets} frames ingested &bull; Safe parser active
            </p>
          </div>
          <div className="pt-3 border-t border-rule mt-3">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setPasteModalOpen(true)}
              className="w-full text-xs"
            >
              <ClipboardPaste size={14} className="text-brand" />
              Paste JSON Logs
            </Button>
          </div>
        </Panel>
      </div>

      {/* Paste Telemetry Modal */}
      {pasteModalOpen && (
        <div className="fixed inset-0 z-50 bg-ink/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-raised border border-rule rounded-2xl w-full max-w-2xl p-6 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileCode size={20} className="text-brand" />
                <h3 className="font-bold text-base text-ink">Paste Packet Telemetry JSON</h3>
              </div>
              <button
                type="button"
                onClick={() => setPasteModalOpen(false)}
                className="text-ink-3 hover:text-ink text-sm font-semibold p-1 cursor-pointer"
              >
                ✕
              </button>
            </div>
            <p className="text-xs text-ink-2 mb-3">
              Paste an array of packet objects (e.g. from Wireshark JSON export, Zeek, or custom logs).
            </p>
            <textarea
              value={pasteContent}
              onChange={(e) => setPasteContent(e.target.value)}
              placeholder='[\n  {\n    "frame_number": 1,\n    "protocol": "TCP",\n    "source_ip": "192.168.1.50",\n    "destination_ip": "10.0.0.12",\n    "source_port": 54120,\n    "destination_port": 443,\n    "info": "54120 -> 443 [SYN] Seq=0"\n  }\n]'
              className="w-full h-56 p-3 bg-sunk rounded-[10px] font-mono text-xs text-ink border border-rule focus:outline-none focus:border-brand field"
            />
            <div className="flex justify-end gap-2 mt-4">
              <Button variant="secondary" size="sm" onClick={() => setPasteModalOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" size="sm" onClick={handlePasteSubmit}>
                Analyze Telemetry
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
