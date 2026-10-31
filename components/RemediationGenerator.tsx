"use client";

import React, { useState } from "react";
import {
  Terminal,
  ShieldCheck,
  Download,
  Copy,
  Check,
  Sliders,
  FileCode,
  ShieldAlert,
  Server,
  Wrench,
  AlertCircle,
} from "lucide-react";
import { Button, Chip, Swatch, cn } from "./ui";
import { Finding } from "@/lib/engine/types";
import { toast } from "sonner";

interface RemediationGeneratorProps {
  findings: Finding[];
  captureName: string;
}

export function RemediationGenerator({ findings, captureName }: RemediationGeneratorProps) {
  const [activeTab, setActiveTab] = useState<"IPTABLES" | "SNORT" | "CISCO" | "CHECKLIST">("IPTABLES");
  const [copiedType, setCopiedType] = useState<string | null>(null);

  // Synthesize Linux iptables script
  const iptablesScript = React.useMemo(() => {
    const lines = [
      "#!/bin/bash",
      "# ====================================================================",
      `# PacketFlow Automated Incident Response & Hardening Script`,
      `# Target Capture: ${captureName}`,
      `# Generated: ${new Date().toISOString()}`,
      "# ====================================================================",
      "",
      "set -e",
      "echo '[+] Applying PacketFlow security remediation rules...'",
      "",
      "# 1. Flush stale temporary chains or create custom isolation chain",
      "iptables -N PACKETFLOW_BLOCK 2>/dev/null || true",
      "iptables -F PACKETFLOW_BLOCK",
      "",
    ];

    findings.forEach((f, idx) => {
      lines.push(`# Finding [${f.id}]: ${f.issue_title} (${f.severity})`);
      if (f.remediation_rules?.iptables) {
        lines.push(f.remediation_rules.iptables);
      } else {
        lines.push(`# Recommended Immediate Action: ${f.recommended_remediation.immediate_action}`);
      }
      lines.push("");
    });

    lines.push("# Ensure PACKETFLOW_BLOCK chain is evaluated first on INPUT");
    lines.push("iptables -C INPUT -j PACKETFLOW_BLOCK 2>/dev/null || iptables -I INPUT 1 -j PACKETFLOW_BLOCK");
    lines.push("");
    lines.push("echo '[✔] All defensive firewall rules successfully applied.'");
    return lines.join("\n");
  }, [findings, captureName]);

  // Synthesize Snort / Suricata IDS rules
  const snortRules = React.useMemo(() => {
    const lines = [
      "# ====================================================================",
      "# PacketFlow Snort / Suricata Intrusion Detection Signatures",
      `# Source: ${captureName} | Auto-generated: ${new Date().toISOString()}`,
      "# ====================================================================",
      "",
    ];

    let count = 0;
    findings.forEach(f => {
      if (f.remediation_rules?.snort) {
        lines.push(`# ${f.id} - ${f.issue_title}`);
        lines.push(f.remediation_rules.snort);
        lines.push("");
        count++;
      }
    });

    if (count === 0) {
      lines.push("# No explicit IDS signatures generated for current operational findings.");
    }

    return lines.join("\n");
  }, [findings, captureName]);

  // Synthesize Cisco IOS commands
  const ciscoScript = React.useMemo(() => {
    const lines = [
      "! ====================================================================",
      "! PacketFlow Cisco IOS Switch & Router Hardening Commands",
      `! Generated for: ${captureName}`,
      "! ====================================================================",
      "configure terminal",
      "",
    ];

    let count = 0;
    findings.forEach(f => {
      if (f.remediation_rules?.cisco) {
        lines.push(`! Finding [${f.id}]: ${f.issue_title}`);
        lines.push(f.remediation_rules.cisco);
        lines.push("");
        count++;
      }
    });

    lines.push("end");
    lines.push("write memory");
    return lines.join("\n");
  }, [findings, captureName]);

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(label);
    toast.success(`${label} copied to clipboard!`);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const downloadFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast.success(`Downloaded ${filename}`);
  };

  return (
    <div className="space-y-6">
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-raised border border-rule rounded-card p-5">
          <div className="flex items-center gap-2 text-ink-2 text-xs font-semibold uppercase tracking-wider">
            <Terminal size={15} className="text-brand" />
            <span>Linux iptables</span>
          </div>
          <div className="text-xl font-bold font-mono text-ink mt-2">
            Automated .sh Script
          </div>
          <p className="text-xs text-ink-2 mt-1">
            Immediate shell drops and rate-limiting rules generated for all malicious hosts.
          </p>
        </div>

        <div className="bg-raised border border-rule rounded-card p-5">
          <div className="flex items-center gap-2 text-ink-2 text-xs font-semibold uppercase tracking-wider">
            <ShieldCheck size={15} className="text-green-600" />
            <span>IDS Signatures</span>
          </div>
          <div className="text-xl font-bold font-mono text-ink mt-2">
            Snort & Suricata
          </div>
          <p className="text-xs text-ink-2 mt-1">
            Compliant rule signatures with unique SIDs for zero-day attack monitoring.
          </p>
        </div>

        <div className="bg-raised border border-rule rounded-card p-5">
          <div className="flex items-center gap-2 text-ink-2 text-xs font-semibold uppercase tracking-wider">
            <Server size={15} className="text-blue-600" />
            <span>Switch Infrastructure</span>
          </div>
          <div className="text-xl font-bold font-mono text-ink mt-2">
            Cisco IOS Hardening
          </div>
          <p className="text-xs text-ink-2 mt-1">
            Hardware-level Dynamic ARP Inspection, DHCP snooping, and MSS clamping.
          </p>
        </div>
      </div>

      {/* Main Tabbed Terminal Viewer */}
      <div className="bg-raised border border-rule rounded-card overflow-hidden shadow-sm">
        {/* Navigation Tabs Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-sunk/60 px-4 py-3">
          <div className="flex items-center gap-1.5">
            {[
              { id: "IPTABLES", label: "Linux iptables (remediation.sh)", icon: Terminal },
              { id: "SNORT", label: "Snort / Suricata Rules", icon: ShieldCheck },
              { id: "CISCO", label: "Cisco Switch Config", icon: Server },
              { id: "CHECKLIST", label: "Action Checklist", icon: Wrench },
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={cn(
                    "flex items-center gap-2 px-3 py-1.5 rounded-[10px] text-xs font-semibold transition-colors",
                    activeTab === tab.id
                      ? "bg-raised text-ink border border-rule shadow-xs"
                      : "text-ink-2 hover:text-ink hover:bg-raised-hover"
                  )}
                >
                  <Icon size={14} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            {activeTab === "IPTABLES" && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(iptablesScript, "iptables script")}
                >
                  {copiedType === "iptables script" ? <Check size={13} /> : <Copy size={13} />}
                  <span>Copy Script</span>
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => downloadFile(iptablesScript, "remediation.sh")}
                >
                  <Download size={13} />
                  <span>Download remediation.sh</span>
                </Button>
              </>
            )}

            {activeTab === "SNORT" && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(snortRules, "Snort rules")}
                >
                  {copiedType === "Snort rules" ? <Check size={13} /> : <Copy size={13} />}
                  <span>Copy Rules</span>
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => downloadFile(snortRules, "packetflow_signatures.rules")}
                >
                  <Download size={13} />
                  <span>Download .rules</span>
                </Button>
              </>
            )}

            {activeTab === "CISCO" && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(ciscoScript, "Cisco config")}
                >
                  {copiedType === "Cisco config" ? <Check size={13} /> : <Copy size={13} />}
                  <span>Copy Config</span>
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => downloadFile(ciscoScript, "cisco_hardening.cfg")}
                >
                  <Download size={13} />
                  <span>Download .cfg</span>
                </Button>
              </>
            )}
          </div>
        </div>

        {/* Tab Contents */}
        <div className="p-6">
          {activeTab === "IPTABLES" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-ink-2">
                <span>Executable bash script formatted for Ubuntu / Debian / RHEL systems:</span>
                <span className="font-mono text-[11px] bg-sunk px-2 py-0.5 rounded border border-rule-soft">chmod +x remediation.sh && sudo ./remediation.sh</span>
              </div>
              <pre className="p-4 bg-canvas rounded-[10px] border border-rule font-mono text-xs text-ink leading-relaxed overflow-x-auto max-h-[460px]">
                {iptablesScript}
              </pre>
            </div>
          )}

          {activeTab === "SNORT" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-ink-2">
                <span>IDS signatures for `/etc/snort/rules/local.rules` or `/etc/suricata/rules`:</span>
                <span className="font-mono text-[11px] bg-sunk px-2 py-0.5 rounded border border-rule-soft">snort -T -c /etc/snort/snort.conf</span>
              </div>
              <pre className="p-4 bg-canvas rounded-[10px] border border-rule font-mono text-xs text-ink leading-relaxed overflow-x-auto max-h-[460px]">
                {snortRules}
              </pre>
            </div>
          )}

          {activeTab === "CISCO" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-ink-2">
                <span>CLI commands for Cisco Catalyst / Enterprise managed layer 2/3 switches:</span>
                <span className="font-mono text-[11px] bg-sunk px-2 py-0.5 rounded border border-rule-soft">Switch# copy running-config startup-config</span>
              </div>
              <pre className="p-4 bg-canvas rounded-[10px] border border-rule font-mono text-xs text-ink leading-relaxed overflow-x-auto max-h-[460px]">
                {ciscoScript}
              </pre>
            </div>
          )}

          {activeTab === "CHECKLIST" && (
            <div className="space-y-4">
              <div className="text-xs text-ink-2">
                Interactive incident response checklist tailored to the {findings.length} detected findings:
              </div>

              <div className="space-y-3">
                {findings.map(f => (
                  <div
                    key={f.id}
                    className="p-4 bg-canvas border border-rule rounded-[10px] space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-ink">{f.id}</span>
                        <h4 className="text-sm font-semibold text-ink">{f.issue_title}</h4>
                      </div>
                      <Chip tone={f.severity === "CRITICAL" ? "flag" : f.severity === "HIGH" ? "warn" : "muted"}>
                        {f.severity}
                      </Chip>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="p-3 bg-red-500/5 border border-red-500/20 rounded-[8px]">
                        <div className="font-bold text-red-600 flex items-center gap-1.5 uppercase text-[10px]">
                          <AlertCircle size={12} />
                          Immediate Containment Step
                        </div>
                        <p className="text-ink mt-1 text-[11px] leading-relaxed">
                          {f.recommended_remediation.immediate_action}
                        </p>
                      </div>

                      <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-[8px]">
                        <div className="font-bold text-blue-600 flex items-center gap-1.5 uppercase text-[10px]">
                          <ShieldCheck size={12} />
                          Long-Term Architectural Fix
                        </div>
                        <p className="text-ink mt-1 text-[11px] leading-relaxed">
                          {f.recommended_remediation.long_term_fix}
                        </p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
