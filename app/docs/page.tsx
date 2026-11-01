"use client";

import Link from "next/link";
import {
  ArrowLeft,
  BookOpen,
  ShieldCheck,
  Code2,
  Terminal,
  Activity,
  Layers,
  Wrench,
  ShieldAlert,
  Lock,
  Zap,
  CheckCircle2,
  Cpu,
  ArrowRight,
  FileCheck2,
} from "lucide-react";
import { Panel, SectionTitle, Chip, Swatch, Button } from "@/components/ui";

export default function DocsPage() {
  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-8">
      {/* Top Breadcrumb & Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-rule">
        <div>
          <div className="flex items-center gap-2.5 text-sm text-ink-3 mb-1.5">
            <Link href="/" className="hover:text-brand hover:underline inline-flex items-center gap-1 font-medium">
              <ArrowLeft size={14} />
              <span>Overview Dashboard</span>
            </Link>
            <span>/</span>
            <span className="text-ink font-semibold">Technical Reference Manual</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-ink">
            System Architecture &amp; Diagnostic Manual
          </h1>
          <p className="text-sm sm:text-base text-ink-2 mt-1">
            Comprehensive technical specification of the diagnostic pipeline, RFC protocol matrices, causal correlation, and safe parsing guarantees.
          </p>
        </div>

        {/* Quick Badge Pills */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-brand-soft text-brand border border-brand/30">
            Engine v2.4 Enterprise
          </span>
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-ok-soft text-ok border border-ok-line">
            RFC Compliant (6 Protocols)
          </span>
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-sunk text-ink-2 border border-rule">
            MITRE ATT&CK v14
          </span>
        </div>
      </div>

      {/* Symmetric Documentation Grid - Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
        {/* Card 1A: Core Diagnostic Architecture */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-rule">
              <div className="h-10 w-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
                <Cpu size={20} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-ink">1. Core Engine Architecture</h2>
                <span className="text-xs text-ink-3">Central diagnostic pipeline &amp; evaluation schema</span>
              </div>
            </div>

            <p className="text-sm sm:text-base text-ink-2 leading-relaxed">
              PacketFlow operates as the central diagnostic engine for automated network telemetry analysis. It parses technical network captures (binary PCAP, PCAPNG, and JSON telemetry streams), categorizes technical findings, differentiates infrastructure outages from targeted attacks, and yields structured diagnoses with verifiable remediation paths.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1.5 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-bold text-ink uppercase tracking-wider block mb-1">
                    Dual Classification
                  </span>
                  <p className="text-xs sm:text-sm text-ink-2 leading-relaxed">
                    Findings are strictly partitioned into <strong>Network Faults (Operational Outages)</strong> or <strong>Security Attacks (Malicious Activity)</strong>.
                  </p>
                </div>
                <div className="pt-2 text-[11px] font-mono text-brand">Strict Schema Compliant</div>
              </div>

              <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1.5 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-bold text-ink uppercase tracking-wider block mb-1">
                    Evidence-Based Verification
                  </span>
                  <p className="text-xs sm:text-sm text-ink-2 leading-relaxed">
                    Every finding cites explicit evidence (Frame numbers, IP pairs, timestamps, and TCP protocol flags) directly extracted from the capture buffer.
                  </p>
                </div>
                <div className="pt-2 text-[11px] font-mono text-ok">Zero Hallucinations Guarantee</div>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-rule text-xs text-ink-3 flex items-center justify-between">
            <span>Execution Model: Deterministic Pure TypeScript Engine</span>
            <Link href="/schema" className="text-brand hover:underline font-semibold inline-flex items-center gap-1">
              <span>View JSON Schema Contract</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </Panel>

        {/* Card 1B: RFC Protocol Compliance Matrix */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-rule">
              <div className="h-10 w-10 rounded-xl bg-ok-soft text-ok flex items-center justify-center shrink-0">
                <FileCheck2 size={20} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-ink">RFC Protocol Standards Matrix</h2>
                <span className="text-xs text-ink-3">Official RFC specifications implemented in detection logic</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1 text-xs">
              {[
                { rfc: "RFC 793", proto: "TCP", desc: "State machine, sequence tracking, window sizing, and out-of-order reassembly." },
                { rfc: "RFC 826", proto: "ARP", desc: "Address resolution, gratuitous reply inspection, and IP collision detection." },
                { rfc: "RFC 1035", proto: "DNS", desc: "Query/response decoding, RCODE parsing, compression pointer validation." },
                { rfc: "RFC 2131", proto: "DHCP", desc: "BOOTP options, rogue OFFER / ACK interception, and gateway fraud." },
                { rfc: "RFC 1191", proto: "PMTUD", desc: "ICMP Type 3 Code 4 fragmentation needed & DF-bit black hole analysis." },
                { rfc: "RFC 2827", proto: "BCP 38", desc: "Network ingress anti-spoofing and self-referential Land attack loops." },
              ].map((item) => (
                <div key={item.rfc} className="p-3 rounded-xl bg-sunk/60 border border-rule space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold font-mono text-brand text-xs">{item.rfc}</span>
                    <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-raised text-ink-2 font-semibold">
                      {item.proto}
                    </span>
                  </div>
                  <p className="text-xs text-ink-2 leading-relaxed">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="pt-4 border-t border-rule text-xs text-ink-3 flex items-center justify-between">
            <span>Protocol Coverage: Ethernet II &bull; IPv4 &bull; TCP &bull; UDP &bull; ICMP &bull; ARP &bull; DNS &bull; DHCP</span>
            <Link href="/packets" className="text-brand hover:underline font-semibold inline-flex items-center gap-1">
              <span>Inspect Live Packet Layers</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </Panel>
      </div>

      {/* Symmetric Documentation Grid - Row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
        {/* Card 2A: Fault vs Attack Differentiation Logic */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-rule">
              <div className="h-10 w-10 rounded-xl bg-warn-soft text-warn flex items-center justify-center shrink-0">
                <ShieldCheck size={20} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-ink">2. Fault vs. Attack Differentiation</h2>
                <span className="text-xs text-ink-3">Minimizing false positives through protocol state machines</span>
              </div>
            </div>

            <p className="text-sm sm:text-base text-ink-2 leading-relaxed">
              Both hardware outages and targeted cyber attacks appear to non-expert users simply as &quot;the network is down&quot;. PacketFlow evaluates low-level protocol states to reliably differentiate benign operational faults from targeted exploits:
            </p>

            <div className="space-y-3 pt-1 text-xs sm:text-sm text-ink-2">
              <div className="p-3.5 rounded-xl bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <Swatch color="var(--color-warn)" />
                  TCP Resets: Application Timeouts vs. Half-Open Scans
                </span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  A burst of TCP RST packets targeting a single port preceded by normal idle duration indicates an operational application crash. Conversely, TCP RSTs elicited across sequential destination ports identify an active half-open SYN scan.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <Swatch color="var(--color-flag)" />
                  DNS Failures: Upstream Outage vs. Rogue Hijacking
                </span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  When DNS queries to public resolvers fail across all domains with SERVFAIL, the engine classifies this as an ISP/gateway failure. However, when an internal workstation emits unauthorized DNS query responses mapping corporate hostnames to local endpoints, it is flagged as a rogue DNS hijack attack.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <Swatch color="var(--color-c-routing)" />
                  ARP Anomalies: Cloned NIC Collision vs. Gateway Poisoning
                </span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Isolated duplicate IP claims are classified as DHCP address conflicts. Rapid, unsolicited Gratuitous ARP replies asserting ownership of the default gateway IP are classified as an active Man-In-The-Middle poisoning attack.
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-rule text-xs text-ink-3 flex items-center justify-between">
            <span>Confidence Scoring: Bayesian Evidence-Weighted Scale (0-100%)</span>
            <Link href="/findings" className="text-brand hover:underline font-semibold inline-flex items-center gap-1">
              <span>View Active Findings Catalog</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </Panel>

        {/* Card 2B: Cross-Layer Causal Correlation Engine */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-rule">
              <div className="h-10 w-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
                <Zap size={20} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-ink">3. Cross-Layer Incident Correlation</h2>
                <span className="text-xs text-ink-3">Causal inference linking root causes to collateral symptoms</span>
              </div>
            </div>

            <p className="text-sm sm:text-base text-ink-2 leading-relaxed">
              Standard network tools report performance faults and security intrusions as isolated phenomena. PacketFlow correlates multi-layer telemetry to discover when an attack is the underlying causal driver of a performance outage:
            </p>

            <div className="space-y-3 pt-1 text-xs sm:text-sm text-ink-2">
              <div className="p-3.5 rounded-xl bg-raised border border-rule space-y-1">
                <span className="font-bold text-amber-600 dark:text-amber-400 flex items-center gap-2">
                  <span>⚡ Induced Operational Symptoms</span>
                </span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  When an attack (e.g. ARP Cache Poisoning or TCP SYN Flood) causes packet drops or link saturation, downstream TCP retransmissions, out-of-order jitter, and RTT latency spikes are explicitly flagged as <em>collateral damage</em> induced by the attack.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-raised border border-rule space-y-1">
                <span className="font-bold text-red-600 dark:text-red-400 flex items-center gap-2">
                  <span>🎯 Root Cause Driver Tagging</span>
                </span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  The primary malicious threat is designated as the root cause driver. Remediating the security incident (e.g. blocking the spoofing MAC) automatically resolves the downstream operational degradation.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <span>⏱️ Chronological Kill-Chain Synthesis</span>
                </span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Reconstructs the full sequence of events across three structured phases: <em>Phase 1: Reconnaissance</em> (scans/sweeps) &rarr; <em>Phase 2: Exploitation</em> (spoofing/injections) &rarr; <em>Phase 3: Induced Degradation</em> (retransmissions/latency).
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-rule text-xs text-ink-3 flex items-center justify-between">
            <span>Executive Synthesis: Clear 2-Sentence Plain-Language Rationale</span>
            <Link href="/topology" className="text-brand hover:underline font-semibold inline-flex items-center gap-1">
              <span>View Threat Topology Map</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </Panel>
      </div>

      {/* Symmetric Documentation Grid - Row 3 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
        {/* Card 3A: Memory Safety & Input Security */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-rule">
              <div className="h-10 w-10 rounded-xl bg-flag-soft text-flag flex items-center justify-center shrink-0">
                <Lock size={20} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-ink">4. Safe Parsing &amp; Threat Modeling</h2>
                <span className="text-xs text-ink-3">Memory bounds checking and zero code execution guarantees</span>
              </div>
            </div>

            <p className="text-sm sm:text-base text-ink-2 leading-relaxed">
              Network captures ingested into diagnostic engines frequently carry corrupt framing, truncated headers, and hostile payloads designed to exploit parser vulnerabilities. PacketFlow guarantees absolute isolation:
            </p>

            <div className="space-y-3 pt-1 text-xs sm:text-sm text-ink-2">
              <div className="p-3.5 rounded-xl bg-sunk/60 border border-rule space-y-1">
                <span className="font-bold text-ink block">Strict Bounds-Checked Slicing</span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Every binary slice of the ingested PCAP buffer is verified against the buffer&apos;s total byte length prior to reading, eliminating out-of-bounds reads and buffer overflows.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-sunk/60 border border-rule space-y-1">
                <span className="font-bold text-ink block">Data-Only Payload Handling</span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Raw payload strings are treated strictly as inert data. Control characters and HTML script tags are sanitized and non-printable bytes are mapped to ASCII dots, preventing XSS and shell injection.
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-sunk/60 border border-rule space-y-1">
                <span className="font-bold text-ink block">Sandboxed Client-Side Parsing</span>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Binary parsing executes directly in the browser runtime. Confidential corporate packets never leave the customer&apos;s local memory unless explicitly submitted to an on-premise REST endpoint.
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-rule text-xs text-ink-3 flex items-center justify-between">
            <span>Guarantees: Zero eval() &bull; Strict Type Checking &bull; Memory Safe</span>
            <Link href="/report" className="text-brand hover:underline font-semibold inline-flex items-center gap-1">
              <span>View Forensic Whitepaper</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </Panel>

        {/* Card 3B: Enterprise Toolset & Severity Hierarchy */}
        <Panel className="p-6 sm:p-8 flex flex-col justify-between h-full border border-rule shadow-xs space-y-6">
          <div className="space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-rule">
              <div className="h-10 w-10 rounded-xl bg-brand-soft text-brand flex items-center justify-center shrink-0">
                <Wrench size={20} />
              </div>
              <div>
                <h2 className="text-xl font-bold text-ink">5. Enterprise Toolset &amp; Triage</h2>
                <span className="text-xs text-ink-3">Forensic modules and incident triage severity levels</span>
              </div>
            </div>

            <p className="text-sm sm:text-base text-ink-2 leading-relaxed">
              PacketFlow pairs deep protocol diagnosis with tactical incident response capabilities, mapping findings into standardized severity buckets:
            </p>

            <div className="space-y-3 pt-1 text-xs sm:text-sm">
              <div className="p-3.5 rounded-xl border border-flag-line bg-flag-soft/20 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-flag uppercase text-xs">CRITICAL Severity</span>
                  <span className="text-[11px] font-mono text-ink-3">Immediate Action Required</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Active intrusions, credential exfiltration, ARP gateway poisoning, rogue DHCP servers, or catastrophic network failure.
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-warn-line bg-warn-soft/20 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-warn uppercase text-xs">HIGH Severity</span>
                  <span className="text-[11px] font-mono text-ink-3">Containment Priority</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  Stealth port reconnaissance, TCP zero-window buffer collapses, MTU fragmentation black holes, and Land attack loops.
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-rule bg-sunk space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-ink uppercase text-xs">MEDIUM &amp; LOW Severity</span>
                  <span className="text-[11px] font-mono text-ink-3">Operational Tuning</span>
                </div>
                <p className="text-xs text-ink-2 leading-relaxed">
                  High RTT latency spikes (&gt;250ms), DNS non-existent domain failures (NXDOMAIN), and moderate packet retransmission overhead.
                </p>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-rule text-xs text-ink-3 flex items-center justify-between">
            <span>Defense Generation: iptables &bull; Snort &bull; Suricata &bull; Cisco IOS</span>
            <Link href="/remediation" className="text-brand hover:underline font-semibold inline-flex items-center gap-1">
              <span>Open Remediation Generator</span>
              <ArrowRight size={12} />
            </Link>
          </div>
        </Panel>
      </div>
    </main>
  );
}
