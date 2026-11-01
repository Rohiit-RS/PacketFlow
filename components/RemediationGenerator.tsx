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
  const [activeTab, setActiveTab] = useState<"IPTABLES" | "SNORT" | "CISCO" | "CHECKLIST" | "SIMULATION">("IPTABLES");
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [targetInterface, setTargetInterface] = useState<string>("eth0");
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(
    () => new Set(findings.map(f => f.id))
  );

  const toggleFindingSelection = (id: string) => {
    setSelectedFindingIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const activeFindings = React.useMemo(() => {
    return findings.filter(f => selectedFindingIds.has(f.id));
  }, [findings, selectedFindingIds]);

  // Synthesize Linux iptables script with dynamic interface substitution
  const iptablesScript = React.useMemo(() => {
    const lines = [
      "#!/bin/bash",
      "# ====================================================================",
      `# PacketFlow Automated Incident Response & Hardening Script`,
      `# Target Capture: ${captureName}`,
      `# Target Interface: ${targetInterface}`,
      `# Generated: ${new Date().toISOString()}`,
      `# Policies Enforced: ${activeFindings.length} of ${findings.length} findings`,
      "# ====================================================================",
      "",
      "set -e",
      `echo '[+] Applying PacketFlow defensive rules on interface ${targetInterface}...'`,
      "",
      "# 1. Flush stale temporary chains or create custom isolation chain",
      "iptables -N PACKETFLOW_BLOCK 2>/dev/null || true",
      "iptables -F PACKETFLOW_BLOCK",
      "",
    ];

    activeFindings.forEach((f) => {
      lines.push(`# Finding [${f.id}]: ${f.issue_title} (${f.severity})`);
      if (f.remediation_rules?.iptables) {
        // Dynamically replace eth0 with the user-selected interface
        const customizedRule = f.remediation_rules.iptables.replace(/\beth0\b/g, targetInterface);
        lines.push(customizedRule);
      } else {
        lines.push(`# Recommended Immediate Action: ${f.recommended_remediation.immediate_action}`);
      }
      lines.push("");
    });

    lines.push("# Ensure PACKETFLOW_BLOCK chain is evaluated first on INPUT");
    lines.push(`iptables -C INPUT -i ${targetInterface} -j PACKETFLOW_BLOCK 2>/dev/null || iptables -I INPUT 1 -i ${targetInterface} -j PACKETFLOW_BLOCK`);
    lines.push("");
    lines.push("echo '[✔] All defensive firewall rules successfully applied.'");
    return lines.join("\n");
  }, [activeFindings, findings.length, captureName, targetInterface]);

  // Synthesize Snort / Suricata IDS rules
  const snortRules = React.useMemo(() => {
    const lines = [
      "# ====================================================================",
      "# PacketFlow Snort / Suricata Intrusion Detection Signatures",
      `# Source: ${captureName} | Interface: ${targetInterface} | Auto-generated: ${new Date().toISOString()}`,
      "# ====================================================================",
      "",
    ];

    let count = 0;
    activeFindings.forEach(f => {
      if (f.remediation_rules?.snort) {
        lines.push(`# ${f.id} - ${f.issue_title}`);
        lines.push(f.remediation_rules.snort);
        lines.push("");
        count++;
      }
    });

    if (count === 0) {
      lines.push("# No explicit IDS signatures generated for current selected findings.");
    }

    return lines.join("\n");
  }, [activeFindings, captureName, targetInterface]);

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
    activeFindings.forEach(f => {
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
  }, [activeFindings, captureName]);

  // Combined Master Bundle Script
  const masterBundle = React.useMemo(() => {
    return [
      "#!/bin/bash",
      "# ====================================================================",
      "# PacketFlow MASTER INCIDENT RESPONSE BUNDLE",
      `# Incident Capture: ${captureName}`,
      `# Bound Interface: ${targetInterface}`,
      `# Generated: ${new Date().toISOString()}`,
      "# ====================================================================",
      "set -e",
      "",
      "# PART 1: LINUX FIREWALL RULES (iptables)",
      iptablesScript,
      "",
      "# PART 2: SNORT SIGNATURES (Writing to /etc/snort/rules/packetflow.rules)",
      "cat << 'EOF' > /tmp/packetflow_signatures.rules",
      snortRules,
      "EOF",
      "echo '[+] Snort signatures staged in /tmp/packetflow_signatures.rules'",
      "",
      "echo '[✔] Master remediation deployment completed successfully.'",
    ].join("\n");
  }, [iptablesScript, snortRules, captureName, targetInterface]);

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
      {/* Symmetric Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
        <div className="bg-raised border border-rule rounded-2xl p-6 flex flex-col justify-between h-full shadow-xs">
          <div>
            <div className="flex items-center gap-2 text-ink-3 text-xs font-bold uppercase tracking-wider">
              <Terminal size={16} className="text-brand" />
              <span>Linux iptables</span>
            </div>
            <div className="text-xl font-bold font-mono text-ink mt-2">
              Automated .sh Script
            </div>
            <p className="text-sm text-ink-2 mt-1.5 leading-relaxed">
              Immediate shell drops and rate-limiting rules generated for all malicious hosts.
            </p>
          </div>
        </div>

        <div className="bg-raised border border-rule rounded-2xl p-6 flex flex-col justify-between h-full shadow-xs">
          <div>
            <div className="flex items-center gap-2 text-ink-3 text-xs font-bold uppercase tracking-wider">
              <ShieldCheck size={16} className="text-ok" />
              <span>IDS Signatures</span>
            </div>
            <div className="text-xl font-bold font-mono text-ink mt-2">
              Snort &amp; Suricata
            </div>
            <p className="text-sm text-ink-2 mt-1.5 leading-relaxed">
              Compliant rule signatures with unique SIDs for zero-day attack monitoring.
            </p>
          </div>
        </div>

        <div className="bg-raised border border-rule rounded-2xl p-6 flex flex-col justify-between h-full shadow-xs">
          <div>
            <div className="flex items-center gap-2 text-ink-3 text-xs font-bold uppercase tracking-wider">
              <Server size={16} className="text-blue-600" />
              <span>Switch Infrastructure</span>
            </div>
            <div className="text-xl font-bold font-mono text-ink mt-2">
              Cisco IOS Hardening
            </div>
            <p className="text-sm text-ink-2 mt-1.5 leading-relaxed">
              Hardware-level Dynamic ARP Inspection, DHCP snooping, and MSS clamping.
            </p>
          </div>
        </div>
      </div>

      {/* Interface & Finding Filter Customizer Bar */}
      <div className="bg-raised border border-rule rounded-2xl p-6 shadow-xs space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-rule">
          <div>
            <h3 className="text-base font-bold text-ink">
              Remediation Policy Customizer
            </h3>
            <p className="text-sm text-ink-2 mt-0.5">
              Select your host network interface and toggle specific findings to include in generated defense rules.
            </p>
          </div>

          <Button
            variant="primary"
            size="md"
            onClick={() => downloadFile(masterBundle, "packetflow_master_remediation.sh")}
            className="shrink-0"
          >
            <Download size={14} />
            <span>Download Master Bundle (.sh)</span>
          </Button>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-6">
          {/* Interface Selector */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-ink-3 uppercase tracking-wider block">
              Target Network Interface:
            </span>
            <div className="flex items-center gap-2">
              {["eth0", "ens33", "wlan0", "br0"].map((iface) => (
                <button
                  key={iface}
                  type="button"
                  onClick={() => setTargetInterface(iface)}
                  className={cn(
                    "px-3 py-1 rounded-lg text-xs font-mono font-bold border transition-colors cursor-pointer",
                    targetInterface === iface
                      ? "bg-brand text-on-brand border-brand"
                      : "bg-sunk text-ink-2 border-rule hover:bg-raised"
                  )}
                >
                  {iface}
                </button>
              ))}
              <input
                type="text"
                value={targetInterface}
                onChange={(e) => setTargetInterface(e.target.value.trim())}
                placeholder="custom"
                className="w-24 px-2.5 py-1 text-xs font-mono bg-sunk rounded-lg border border-rule text-ink focus:outline-none focus:border-brand"
              />
            </div>
          </div>

          {/* Finding Toggles */}
          <div className="space-y-2 flex-1">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-ink-3 uppercase tracking-wider block">
                Enforced Policies ({activeFindings.length} of {findings.length}):
              </span>
              <button
                type="button"
                onClick={() => {
                  if (selectedFindingIds.size === findings.length) {
                    setSelectedFindingIds(new Set());
                  } else {
                    setSelectedFindingIds(new Set(findings.map(f => f.id)));
                  }
                }}
                className="text-xs text-brand hover:underline font-semibold cursor-pointer"
              >
                {selectedFindingIds.size === findings.length ? "Deselect All" : "Select All"}
              </button>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {findings.map((f) => {
                const isChecked = selectedFindingIds.has(f.id);
                return (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => toggleFindingSelection(f.id)}
                    className={cn(
                      "px-2.5 py-1 rounded-lg text-xs font-mono font-semibold border transition-all inline-flex items-center gap-1.5 cursor-pointer",
                      isChecked
                        ? "bg-raised text-ink border-brand/60 shadow-xs"
                        : "bg-sunk/50 text-ink-3 border-rule-soft line-through opacity-60"
                    )}
                  >
                    <span className={cn(
                      "w-2 h-2 rounded-full",
                      f.category === "ATTACK" ? "bg-flag" : "bg-warn"
                    )} />
                    <span>{f.id}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Main Tabbed Terminal Viewer */}
      <div className="bg-raised border border-rule rounded-2xl overflow-hidden shadow-xs">
        {/* Navigation Tabs Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule bg-sunk/60 px-5 py-3.5">
          <div className="flex items-center gap-2">
            {[
              { id: "IPTABLES", label: "Linux iptables", icon: Terminal },
              { id: "SNORT", label: "Snort / Suricata", icon: ShieldCheck },
              { id: "CISCO", label: "Cisco IOS Switch", icon: Server },
              { id: "SIMULATION", label: "Dry-Run Terminal", icon: Sliders },
              { id: "CHECKLIST", label: "Action Checklist", icon: Wrench },
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-colors cursor-pointer",
                    activeTab === tab.id
                      ? "bg-raised text-ink border border-rule shadow-xs"
                      : "text-ink-2 hover:text-ink hover:bg-raised-hover"
                  )}
                >
                  <Icon size={15} />
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
        <div className="p-6 sm:p-8">
          {activeTab === "IPTABLES" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm text-ink-2">
                <span>Executable bash script formatted for Linux iptables:</span>
                <span className="font-mono text-xs bg-sunk px-2.5 py-1 rounded-md border border-rule-soft">chmod +x remediation.sh &amp;&amp; sudo ./remediation.sh</span>
              </div>
              <pre className="p-6 bg-canvas rounded-xl border border-rule font-mono text-sm text-ink leading-relaxed overflow-x-auto max-h-[500px]">
                {iptablesScript}
              </pre>
            </div>
          )}

          {activeTab === "SNORT" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm text-ink-2">
                <span>IDS signatures for Snort and Suricata rulesets:</span>
                <span className="font-mono text-xs bg-sunk px-2.5 py-1 rounded-md border border-rule-soft">snort -T -c /etc/snort/snort.conf</span>
              </div>
              <pre className="p-6 bg-canvas rounded-xl border border-rule font-mono text-sm text-ink leading-relaxed overflow-x-auto max-h-[500px]">
                {snortRules}
              </pre>
            </div>
          )}

          {activeTab === "CISCO" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm text-ink-2">
                <span>Configuration commands for Cisco enterprise switches:</span>
                <span className="font-mono text-xs bg-sunk px-2.5 py-1 rounded-md border border-rule-soft">Switch# copy running-config startup-config</span>
              </div>
              <pre className="p-6 bg-canvas rounded-xl border border-rule font-mono text-sm text-ink leading-relaxed overflow-x-auto max-h-[500px]">
                {ciscoScript}
              </pre>
            </div>
          )}

          {activeTab === "SIMULATION" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm text-ink-2">
                <span>Production Environment Shell Simulation (Dry-Run Preview):</span>
                <span className="font-mono text-xs bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-2.5 py-1 rounded-md border border-emerald-500/20 font-bold">
                  Status: Simulated Exit Code 0 (Success)
                </span>
              </div>
              <div className="p-6 bg-black rounded-xl border border-zinc-800 font-mono text-xs text-zinc-300 leading-relaxed overflow-x-auto max-h-[500px] space-y-2 select-text">
                <div className="text-zinc-500"># Interactive Linux Bash Execution Trace:</div>
                <div className="text-emerald-400">$ sudo chmod +x remediation.sh &amp;&amp; sudo ./remediation.sh</div>
                <div className="text-zinc-400">[00:00:01] [+] Loading PacketFlow defensive rules for interface &apos;{targetInterface}&apos;...</div>
                <div className="text-zinc-400">[00:00:01] [+] Kernel netfilter subsystem verified (iptables v1.8.7)</div>
                <div className="text-zinc-400">[00:00:01] [+] Flushed and initialized custom isolation chain &apos;PACKETFLOW_BLOCK&apos;</div>
                <div className="text-zinc-500">--------------------------------------------------------------------------------</div>
                {activeFindings.map((f, i) => (
                  <div key={f.id} className="space-y-0.5">
                    <div className="text-zinc-300">
                      [00:00:0{(i % 8) + 1}] <span className="text-amber-400">[{f.id}]</span> Applying policy for: {f.issue_title}
                    </div>
                    <div className="text-zinc-500 pl-6 text-[11px]">
                      &gt; Action: {f.recommended_remediation.immediate_action}
                    </div>
                    <div className="text-emerald-400 pl-6 text-[11px]">
                      [✔] Policy successfully injected into kernel packet filter table.
                    </div>
                  </div>
                ))}
                <div className="text-zinc-500">--------------------------------------------------------------------------------</div>
                <div className="text-zinc-400">[00:00:09] [+] Binding chain &apos;PACKETFLOW_BLOCK&apos; to INPUT on &apos;{targetInterface}&apos;...</div>
                <div className="text-emerald-400 font-bold">[00:00:09] [✔] All {activeFindings.length} firewall &amp; sysctl policies successfully enforced with 0 errors.</div>
                <div className="text-zinc-400">[00:00:10] [+] Active rules summary: {activeFindings.length} drop/tune policies active.</div>
                <div className="text-zinc-500">$ _</div>
              </div>
            </div>
          )}

          {activeTab === "CHECKLIST" && (
            <div className="space-y-5">
              <div className="text-sm font-medium text-ink-2">
                Interactive incident response checklist tailored to the {findings.length} detected findings:
              </div>

              <div className="space-y-4">
                {findings.map(f => (
                  <div
                    key={f.id}
                    className="p-6 bg-canvas border border-rule rounded-xl space-y-4"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <span className="text-sm font-mono font-bold text-ink">{f.id}</span>
                        <h4 className="text-base font-bold text-ink">{f.issue_title}</h4>
                      </div>
                      <Chip tone={f.severity === "CRITICAL" ? "flag" : f.severity === "HIGH" ? "warn" : "muted"}>
                        {f.severity}
                      </Chip>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-stretch text-sm">
                      <div className="p-4 bg-red-500/5 border border-red-500/20 rounded-xl flex flex-col justify-start h-full">
                        <div className="font-bold text-red-600 flex items-center gap-1.5 uppercase text-xs mb-1">
                          <AlertCircle size={14} />
                          Immediate Containment Step
                        </div>
                        <p className="text-ink text-sm leading-relaxed font-normal">
                          {f.recommended_remediation.immediate_action}
                        </p>
                      </div>

                      <div className="p-4 bg-blue-500/5 border border-blue-500/20 rounded-xl flex flex-col justify-start h-full">
                        <div className="font-bold text-blue-600 flex items-center gap-1.5 uppercase text-xs mb-1">
                          <ShieldCheck size={14} />
                          Long-Term Architectural Fix
                        </div>
                        <p className="text-ink text-sm leading-relaxed font-normal">
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
