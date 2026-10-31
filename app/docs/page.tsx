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
} from "lucide-react";
import { Panel, SectionTitle, Chip, Swatch } from "@/components/ui";

export default function DocsPage() {
  return (
    <main className="mx-auto w-full max-w-[1360px] px-4 sm:px-8 py-6 sm:py-8 space-y-7">
      {/* Top Breadcrumb Navigation */}
      <div className="flex items-center justify-between gap-4 pb-2 border-b border-rule">
        <div>
          <div className="flex items-center gap-2 text-xs text-ink-3 mb-1">
            <Link href="/" className="hover:text-brand hover:underline inline-flex items-center gap-1">
              <ArrowLeft size={12} />
              <span>Overview</span>
            </Link>
            <span>/</span>
            <span className="text-ink font-semibold">Documentation &amp; Reference</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-ink">
            System Architecture &amp; Detection Manual
          </h1>
          <p className="text-xs sm:text-sm text-ink-2 mt-0.5">
            Technical specification of the diagnostic pipeline, detection algorithms, differentiation heuristics, and safe parsing guarantees.
          </p>
        </div>
      </div>

      {/* Grid of Documentation Sections */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Core Architecture & Differentiation */}
        <div className="lg:col-span-8 space-y-6">
          {/* Section 1: Engine Overview */}
          <Panel className="p-6 space-y-3.5">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-[8px] bg-brand-soft text-brand flex items-center justify-center">
                <Activity size={18} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-ink">1. Core Engine Overview</h2>
                <span className="text-xs text-ink-3">Central diagnostic pipeline</span>
              </div>
            </div>

            <p className="text-[0.9375rem] text-ink-2 leading-[1.6]">
              PacketFlow functions as a central diagnostic engine for automated network capture analysis. It ingests technical network telemetry (extracted PCAP metadata, packet logs, and flow summaries), identifies network faults and malicious cyber attacks, differentiates outages from security incidents, and outputs structured, human-readable diagnoses with clear remediation steps.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
              <div className="p-3.5 rounded-[10px] bg-sunk/60 border border-rule space-y-1">
                <span className="text-xs font-bold text-ink block">Dual Categorization</span>
                <p className="text-xs text-ink-2">
                  Telemetry findings are categorized strictly into <strong>Network Faults (Operational Issues)</strong> or <strong>Security Attacks (Malicious Activity)</strong>.
                </p>
              </div>

              <div className="p-3.5 rounded-[10px] bg-sunk/60 border border-rule space-y-1">
                <span className="text-xs font-bold text-ink block">Evidence-Based Findings</span>
                <p className="text-xs text-ink-2">
                  Every finding cites specific evidence (Frame numbers, IP pairs, timestamps, and TCP protocol flags) directly extracted from input captures.
                </p>
              </div>
            </div>
          </Panel>

          {/* Section 2: Fault vs Attack Differentiation */}
          <Panel className="p-6 space-y-3.5">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-[8px] bg-brand-soft text-brand flex items-center justify-center">
                <ShieldCheck size={18} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-ink">2. Fault vs. Attack Differentiation Logic</h2>
                <span className="text-xs text-ink-3">Minimizing false alarms through heuristic state machines</span>
              </div>
            </div>

            <p className="text-[0.9375rem] text-ink-2 leading-[1.6]">
              Both outages and cyber attacks present to end-users as &quot;the network is broken&quot;. PacketFlow evaluates protocol states to distinguish benign operational failures from targeted malicious activities:
            </p>

            <div className="space-y-2.5 pt-1 text-xs text-ink-2">
              <div className="p-3 rounded-[10px] bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <Swatch color="var(--color-warn)" />
                  TCP Resets: Closed Ports vs. Connection Tear-Down
                </span>
                <p>
                  A burst of TCP RST packets targeting a single port preceded by normal idle duration is diagnosed as an operational application timeout. Conversely, TCP RSTs elicited across sequential destination ports identify a half-open port scan.
                </p>
              </div>

              <div className="p-3 rounded-[10px] bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <Swatch color="var(--color-flag)" />
                  DNS Failures: Upstream Outage vs. Rogue Hijacking
                </span>
                <p>
                  When DNS queries to public resolvers fail across all domains with SERVFAIL, the engine classifies this as an ISP/gateway failure. However, when an internal workstation emits unauthorized DNS query responses mapping corporate hostnames to local endpoints, it is flagged as a rogue DNS hijack attack.
                </p>
              </div>

              <div className="p-3 rounded-[10px] bg-raised border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-2">
                  <Swatch color="var(--color-c-routing)" />
                  ARP Anomalies: Cloned NIC vs. Gateway Cache Poisoning
                </span>
                <p>
                  Isolated duplicate IP claims are classified as DHCP address conflicts. Rapid, unsolicited Gratuitous ARP replies asserting ownership of the default gateway IP are classified as an active Man-In-The-Middle poisoning attack.
                </p>
              </div>
            </div>
          </Panel>

          {/* Section 3: Safe Parsing & Threat Modeling */}
          <Panel className="p-6 space-y-3.5">
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-[8px] bg-brand-soft text-brand flex items-center justify-center">
                <Lock size={18} />
              </div>
              <div>
                <h2 className="text-lg font-bold text-ink">3. Safe Parsing &amp; Input Security</h2>
                <span className="text-xs text-ink-3">Memory safety and zero data leakage guarantees</span>
              </div>
            </div>

            <p className="text-[0.9375rem] text-ink-2 leading-[1.6]">
              Packet captures frequently contain corrupt headers, fragmented frames, and attacker payloads containing executable scripts or exploit payloads. PacketFlow enforces strict safety boundaries:
            </p>

            <ul className="list-disc pl-5 space-y-1.5 text-xs text-ink-2">
              <li>
                <strong>Strict Bounds Checking:</strong> Every slice of the binary capture buffer is verified against total length before reading, preventing memory buffer overruns on malformed inputs.
              </li>
              <li>
                <strong>Data-Only Payload Handling:</strong> Raw packet payloads are treated strictly as read-only binary data. HTML characters (<code className="font-mono bg-sunk px-1 rounded">&lt;</code>, <code className="font-mono bg-sunk px-1 rounded">&gt;</code>, <code className="font-mono bg-sunk px-1 rounded">&amp;</code>) are escaped, and non-printable control bytes are converted to ASCII dots (<code className="font-mono bg-sunk px-1 rounded">.</code>) before display.
              </li>
              <li>
                <strong>Client-Side Processing:</strong> Binary parsing runs in pure TypeScript in the browser. Confidential network captures never leave the local environment unless explicitly posted to the REST API.
              </li>
            </ul>
          </Panel>
        </div>

        {/* Right Column: Reference Matrices & Protocols */}
        <div className="lg:col-span-4 space-y-6">
          {/* RFC Protocol Compliance */}
          <div>
            <SectionTitle sub="Standards implemented in detection logic">
              RFC Protocol Matrix
            </SectionTitle>
            <Panel className="p-4 space-y-2.5 text-xs">
              {[
                { rfc: "RFC 793", label: "Transmission Control Protocol (TCP)", desc: "State machine, sequence tracking, window sizing" },
                { rfc: "RFC 826", label: "Address Resolution Protocol (ARP)", desc: "Gratuitous ARP inspection, duplicate IP detection" },
                { rfc: "RFC 1035", label: "Domain Name System (DNS)", desc: "Query/response decoding, RCODE parsing, compression" },
                { rfc: "RFC 2131", label: "Dynamic Host Configuration (DHCP)", desc: "BOOTP options, rogue offer and gateway checks" },
                { rfc: "RFC 1191", label: "Path MTU Discovery (PMTUD)", desc: "ICMP Type 3 Code 4 fragmentation needed handling" },
                { rfc: "RFC 2827", label: "Network Ingress Filtering", desc: "Anti-spoofing and malformed Land attack detection" },
              ].map((item) => (
                <div key={item.rfc} className="p-2.5 rounded-[8px] bg-sunk/60 border border-rule">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="font-bold font-mono text-brand">{item.rfc}</span>
                  </div>
                  <div className="font-semibold text-ink">{item.label}</div>
                  <div className="text-[11px] text-ink-3 mt-0.5">{item.desc}</div>
                </div>
              ))}
            </Panel>
          </div>

          {/* Enterprise Capabilities */}
          <div>
            <SectionTitle sub="Forensic & response features">
              Enterprise Toolset
            </SectionTitle>
            <Panel className="p-4 space-y-2.5 text-xs">
              <div className="p-2.5 rounded-[8px] bg-sunk border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-1.5">
                  <Activity size={13} className="text-brand" />
                  <span>Interactive Threat Topology (/topology)</span>
                </span>
                <p className="text-ink-2 text-[11px]">
                  Real-time SVG host communication matrix with animated traffic vectors and threat halos.
                </p>
              </div>

              <div className="p-2.5 rounded-[8px] bg-sunk border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-1.5">
                  <Wrench size={13} className="text-ok" />
                  <span>Automated Remediation (/remediation)</span>
                </span>
                <p className="text-ink-2 text-[11px]">
                  Generates ready-to-run iptables scripts, Snort/Suricata IDS rules, and Cisco configs.
                </p>
              </div>

              <div className="p-2.5 rounded-[8px] bg-sunk border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-1.5">
                  <ShieldCheck size={13} className="text-flag" />
                  <span>Forensic Audit & Hashes (/report)</span>
                </span>
                <p className="text-ink-2 text-[11px]">
                  SHA-256 and MD5 chain-of-custody checksums with print/PDF-ready incident whitepapers.
                </p>
              </div>

              <div className="p-2.5 rounded-[8px] bg-sunk border border-rule space-y-1">
                <span className="font-bold text-ink flex items-center gap-1.5">
                  <Code2 size={13} className="text-brand" />
                  <span>Follow TCP Stream Reconstructor</span>
                </span>
                <p className="text-ink-2 text-[11px]">
                  Reconstructs conversational client-server payloads in ASCII and Hex with full XSS sanitization.
                </p>
              </div>
            </Panel>
          </div>

          {/* Severity Classification */}
          <div>
            <SectionTitle sub="Triage hierarchy">
              Severity Definitions
            </SectionTitle>
            <Panel className="p-4 space-y-2 text-xs">
              <div className="p-2.5 rounded-[8px] border border-flag-line bg-flag-soft/20 space-y-1">
                <span className="font-bold text-flag uppercase">CRITICAL</span>
                <p className="text-ink-2 text-[11px]">
                  Active breaches, credential exfiltration, ARP gateway hijacking, or total network throughput collapse.
                </p>
              </div>

              <div className="p-2.5 rounded-[8px] border border-warn-line bg-warn-soft/20 space-y-1">
                <span className="font-bold text-warn uppercase">HIGH</span>
                <p className="text-ink-2 text-[11px]">
                  Systematic stealth reconnaissance scans, zero-window receiver pauses, and MTU fragmentation black holes.
                </p>
              </div>

              <div className="p-2.5 rounded-[8px] border border-rule bg-sunk space-y-1">
                <span className="font-bold text-ink uppercase">MEDIUM &amp; LOW</span>
                <p className="text-ink-2 text-[11px]">
                  Isolated latency spikes, non-critical DNS lookup errors, and minor packet retransmission overhead.
                </p>
              </div>
            </Panel>
          </div>
        </div>
      </div>
    </main>
  );
}
