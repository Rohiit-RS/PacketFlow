"use client";

import { useState } from "react";
import { FileJson, Copy, Check, Download } from "lucide-react";
import { Button, Panel, SectionTitle, Chip } from "./ui";
import { DiagnosticReport } from "@/lib/engine/types";
import { toast } from "sonner";

interface SchemaViewerProps {
  report: DiagnosticReport;
}

export function SchemaViewer({ report }: SchemaViewerProps) {
  const [copied, setCopied] = useState(false);
  const jsonString = JSON.stringify(report, null, 2);

  const handleCopy = () => {
    try {
      navigator.clipboard.writeText(jsonString);
      setCopied(true);
      toast.success("Diagnostic JSON copied to clipboard!");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy JSON.");
    }
  };

  const handleDownload = () => {
    try {
      const blob = new Blob([jsonString], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `packetflow-diagnostic-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("JSON file downloaded!");
    } catch {
      toast.error("Download failed.");
    }
  };

  return (
    <div className="space-y-4">
      <SectionTitle
        sub="Strict specification output matching the exact JSON schema required by the diagnostic platform"
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={handleDownload}>
              <Download size={14} />
              <span>Download .json</span>
            </Button>
            <Button variant="primary" size="sm" onClick={handleCopy}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              <span>{copied ? "Copied!" : "Copy JSON Schema"}</span>
            </Button>
          </div>
        }
      >
        Diagnostic Engine JSON Schema
      </SectionTitle>

      <Panel className="p-4 bg-sunk/60 overflow-hidden">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-rule text-xs text-ink-3">
          <div className="flex items-center gap-2">
            <FileJson size={14} className="text-brand" />
            <span className="font-mono font-semibold">diagnostic_report.json</span>
          </div>
          <span className="font-mono text-[11px]">{jsonString.length} bytes</span>
        </div>

        <pre className="p-3 bg-raised rounded-xl border border-rule font-mono text-xs text-ink overflow-x-auto max-h-[500px] overflow-y-auto leading-relaxed select-text">
          {jsonString}
        </pre>
      </Panel>
    </div>
  );
}
