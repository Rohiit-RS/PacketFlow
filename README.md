# PacketFlow &bull; Automated Network Packet Analysis & Security Diagnostic Engine

[![Next.js 15](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![React 19](https://img.shields.io/badge/React-19-blue?style=for-the-badge&logo=react)](https://react.dev/)
[![Tailwind CSS v4](https://img.shields.io/badge/Tailwind-v4-38bdf8?style=for-the-badge&logo=tailwindcss)](https://tailwindcss.com/)
[![TypeScript 5](https://img.shields.io/badge/TypeScript-5.7-3178c6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

> **24-Hour Cybersecurity Hackathon &bull; IIITDM Kancheepuram**  
> **Track:** Network Track &bull; *Diagnosing Network Problems from Packet Captures*

---

## 1. Executive Summary & Problem Context

Small offices, university computer labs, and campus departments depend on their local networks every day. However, most lack a dedicated network administrator or security operations team. When the network becomes sluggish, drops connections, or behaves erratically, the traditional diagnostic procedure requires opening a packet capture (`.pcap`) and inspecting raw hex frames line-by-line.

This requires deep protocol expertise and is time-prohibitive for students and beginners. More critically, **it is notoriously difficult to separate a benign operational outage (e.g. cable failure, MTU mismatch, buffer exhaustion) from a targeted cyber attack (e.g. ARP poisoning, stealth port scans, covert DNS exfiltration) hiding in the exact same traffic stream.**

**PacketFlow** solves this challenge by serving as an **Automated Diagnostic & Differentiation Engine**. It ingests technical packet telemetry and raw PCAP captures, applies 100% custom protocol state machines, explicitly distinguishes outages from attacks with weighted confidence scores, and outputs human-readable diagnoses with clear remediation steps: **Immediate Containment** and **Long-Term Configuration**.

---

## 2. Multi-Page Architecture Overview

PacketFlow is built on Next.js 15 App Router as a modern, multi-page application where every view, finding dossier, and evidence frame citation has its own dedicated URL:

| Page Route | Module Name | Primary Forensic Capabilities |
|---|---|---|
| [`/`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/page.tsx) | **Executive Dashboard** | Drag-and-drop PCAP ingestion, 7 one-click test scenarios, Health Verdict Hero, and KPI metrics. |
| [`/findings`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/findings/page.tsx) | **Diagnostic Findings** | Full findings catalog with search, severity filter pills, and MITRE technique tags. |
| [`/findings/[id]`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/findings/[id]/page.tsx) | **Finding Dossier** | Deep-dive finding view with plain-language explanation, root cause analysis, clickable frame evidence links, and generated defense commands. |
| [`/packets`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/packets/page.tsx) | **Deep Packet Inspector** | Wireshark display filter bar, traffic burst histogram, layer-by-layer decode, safe hex/ASCII viewer, and **Follow TCP Stream** reconstructor. |
| [`/flows`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/flows/page.tsx) | **Flow Matrix** | Reconstructed bidirectional conversational streams, TCP flags, duration, and byte volume breakdown. |
| [`/topology`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/topology/page.tsx) | **Network Threat Topology** | Interactive SVG node-link graph with pulsing threat indicators, hostile flow vectors, and per-host inspection drawers. |
| [`/remediation`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/remediation/page.tsx) | **Automated Remediation** | One-click synthesis of ready-to-execute Linux `iptables` scripts (`remediation.sh`), Snort/Suricata IDS rules (`.rules`), and Cisco switch configs. |
| [`/report`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/report/page.tsx) | **Forensic Audit Report** | Print/PDF-ready incident audit report with cryptographic chain of custody (SHA-256 and MD5 checksums) and radial threat gauge. |
| [`/schema`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/schema/page.tsx) | **Strict JSON Engine Output** | Real-time JSON viewer formatting exact hackathon output schema, with one-click clipboard copy and `.json` export. |
| [`/docs`](file:///c:/Users/rsroh/OneDrive/Desktop/PacketFlow/app/docs/page.tsx) | **Technical Reference Manual** | Exhaustive technical manual detailing detection heuristics, stateful threshold metrics, and REST API specifications. |

---

## 3. Core Capabilities & Detection Matrix

### A. Network Faults (Operational Issues)
1. **TCP Retransmissions & Packet Loss**: Tracks duplicate sequence numbers per flow. Quantifies packet loss percentage and identifies bottlenecked paths.
2. **TCP Window Size Issues (Zero Window Freeze)**: Detects when a receiving endpoint collapses its TCP window to 0, signaling receiver CPU or I/O exhaustion.
3. **Duplicate IP & Addressing Conflicts**: Detects multiple distinct hardware MAC addresses claiming ownership of the identical IP address via ARP broadcasts.
4. **Path MTU Mismatch & Black Hole Routers**: Pinpoints ICMP Type 3 Code 4 (*Destination Unreachable, Fragmentation Needed and DF bit set*) notifications caused by constricted VPN tunnels or VLAN trunks.
5. **DNS Resolver Failures**: Flags anomalous non-zero RCODE responses (NXDOMAIN, SERVFAIL, REFUSED) and query timeout conditions.
6. **Performance & Latency Degradation**: Calculates round-trip-time (RTT) deltas between handshakes and data-acknowledgment sequences, flagging spikes exceeding 250ms.

### B. Security Attacks (Malicious Activity)
1. **Stealth Port Scans** (*MITRE T1046*):
   - **SYN Stealth Scan**: Rapid half-open SYN packets across numerous ports without completing the 3-way handshake.
   - **FIN / NULL / XMAS Scans**: Packets with illegal flag combinations (e.g. FIN+PSH+URG or zero flags) engineered to bypass stateless firewalls.
   - **UDP Port Probing**: Systematic probes triggering closed-port ICMP Port Unreachable bursts.
2. **IP Sweeps & Reconnaissance** (*MITRE T1018*): Single host systematically pinging and mapping sequential internal IP addresses (`/24`) for active nodes.
3. **ARP Spoofing & MITM Poisoning** (*MITRE T1557.002*): Unsolicited Gratuitous ARP replies asserting ownership of the Default Gateway IP (`192.168.1.1`), diverting traffic through an attacker MAC.
4. **Rogue DNS & Domain Hijacking** (*MITRE T1584.002*): Non-gateway internal hosts forging port 53 UDP replies to redirect corporate users to phishing portals.
5. **Rogue DHCP Server Conflict** (*MITRE T1557*): Unauthorized secondary DHCP server offering rogue IP leases, malicious default gateways, and rogue DNS servers.
6. **Traffic Anomalies & Web Exploits** (*MITRE T1190 & T1498.001*):
   - **Land Attack**: Malformed packets where Source IP equals Destination IP and ports match.
   - **Injection Signatures**: Unencrypted payloads matching SQL injection (`OR 1=1`, `UNION SELECT`), path traversal (`../../etc/passwd`), or command shells (`/bin/sh`, `cmd.exe`).
7. **Covert Data Exfiltration** (*MITRE T1071.004*): DNS Tunneling (unusually long query labels with high Shannon entropy and base32/base64 strings exfiltrating data via TXT/A queries).

### C. Fault vs. Attack Differentiation (Crucial Requirement)
Every finding is evaluated by our differentiation logic to prevent false alarms:
* *Why a burst of TCP RSTs is a closed service port vs. a SYN flood.*
* *Why multiple DNS errors represent an upstream ISP outage vs. an active DNS hijack.*
* *Assigns an explicit confidence score (0-100%) and provides root-cause technical rationale.*

---

## 4. Strict Output JSON Schema

The platform's API (`/api/analyze`) and export tools strictly adhere to the required JSON schema:

```json
{
  "summary": {
    "total_packets_analyzed": 30,
    "overall_health_status": "WARNING",
    "primary_classification": "MALICIOUS_ATTACK",
    "executive_summary": "Security analysis identified 1 active cyber threat(s), primarily characterized by Stealth TCP SYN Port Scan Detected from 10.0.0.88. Immediate containment is recommended to prevent unauthorized access or data compromise."
  },
  "findings": [
    {
      "id": "FINDING-001",
      "category": "ATTACK",
      "issue_title": "Stealth TCP SYN Port Scan Detected from 10.0.0.88",
      "severity": "HIGH",
      "confidence_score": 97,
      "plain_language_explanation": "A suspicious device (10.0.0.88) is systematically knocking on dozens of digital doors (ports) on host 10.0.0.12 to find open vulnerabilities, services, or weaknesses to breach.",
      "technical_details": {
        "root_cause": "Host 10.0.0.88 dispatched unsolicited TCP SYN packets across 15 distinct ports (including 21, 22, 23, 25, 53, 80 (+9 more)) without completing standard 3-way handshakes. Characteristic of an automated reconnaissance tool such as Nmap (-sS) or Masscan.",
        "evidence_packets": [
          "Frame #1 TCP [SYN] 10.0.0.88:45021 -> 10.0.0.12:21",
          "Frame #3 TCP [SYN] 10.0.0.88:45022 -> 10.0.0.12:22",
          "Frame #5 TCP [SYN] 10.0.0.88:45023 -> 10.0.0.12:23",
          "Frame #7 TCP [SYN] 10.0.0.88:45025 -> 10.0.0.12:25",
          "Frame #9 TCP [SYN] 10.0.0.88:45053 -> 10.0.0.12:53"
        ]
      },
      "recommended_remediation": {
        "immediate_action": "Block source IP 10.0.0.88 immediately at the perimeter firewall / switch ACL and inspect host 10.0.0.12 for unauthorized inbound connections.",
        "long_term_fix": "Deploy an Intrusion Detection System (Snort/Suricata) with rate-limiting drop rules and ensure unused listening service ports are disabled."
      }
    }
  ]
}
```

---

## 5. Security & Safe Parsing Architecture

* **Bounds-Checked Binary Parsing**: Every byte slice in the PCAP header and packet records is verified against buffer length to prevent memory buffer overruns.
* **Zero Script Execution**: Raw packet payload strings are never evaluated or injected via `dangerouslySetInnerHTML`. All ASCII representations are stripped of non-printable control characters, HTML-escaped (`&`, `<`, `>`, `"`, `'`), and presented inside safe scrollable code blocks.
* **Zero Data Leakage**: By implementing the binary parser in pure TypeScript, PCAP captures can be parsed locally in the client's browser without sending sensitive confidential network packets over the wire.
* **Cryptographic Evidence Integrity**: Computes SHA-256 and MD5 checksums of captures for forensic chain-of-custody verification.
* **No Hardcoded Secrets**: Fully environment-agnostic with zero external API key requirements.

---

## 6. Built-in Test Captures for Judges

In compliance with the Hackathon guidelines (*"Include a few sample captures in your repository so the judges can run your tool without setting up a network"*), PacketFlow provides **7 pre-synthesized test scenarios** accessible via 1-click in the UI or in the `sample-captures/` folder:

1. **`1_arp_spoofing_mitm.pcap`**: Unsolicited gratuitous ARP poison attack diverting client traffic through an attacker MAC.
2. **`2_syn_port_scan.pcap`**: Nmap-style stealth SYN sweep targeting 15 service ports.
3. **`3_tcp_congestion_outage.pcap`**: 58% TCP retransmission loss with zero-window receiver collapse.
4. **`demo_cyber_incident.json`**: Multi-stage attack capture featuring SYN scans, web SQLi payloads, and DNS tunneling.
5. **`demo_operational_fault.json`**: Severe infrastructure failure with duplicate IP ARP conflicts, MTU mismatches, and DNS timeouts.
6. **Rogue DHCP Server Conflict**: Colliding DHCP OFFER frames from an unauthorized gateway plus duplicate IP collision.
7. **Clean High-Performance Baseline**: Pristine TLS 1.3 handshakes, verified DNS resolutions, and zero packet drops.

---

## 7. Local Setup & Running Instructions

### Prerequisites
* Node.js v18.0.0 or higher (v20+ recommended)
* npm, yarn, or pnpm

### Quick Start
```bash
# 1. Clone repository
git clone https://github.com/your-username/PacketFlow.git
cd PacketFlow

# 2. Install dependencies
npm install

# 3. Start local development server
npm run dev
```

Open your browser to `http://localhost:3000`.

### Production Build & Verification
```bash
# Build optimized production bundle
npm run build

# Start production server
npm run start
```

### Testing the REST API via cURL
You can test the engine directly from your terminal by posting any PCAP or JSON file:
```bash
# Binary PCAP
curl -X POST "http://localhost:3000/api/analyze" \
  --data-binary "@sample-captures/1_arp_spoofing_mitm.pcap" \
  -H "Content-Type: application/octet-stream"

# JSON Telemetry
curl -X POST "http://localhost:3000/api/analyze" \
  --data-binary "@sample-captures/demo_cyber_incident.json" \
  -H "Content-Type: application/json"
```

---

## 8. Step-by-Step Vercel Deployment Instructions

PacketFlow is built on **Next.js 15 App Router** and is 100% compatible with Vercel serverless functions with zero configuration needed.

### Method A: Deploy via Vercel Web Dashboard (Recommended)

1. **Push to GitHub**:
   ```bash
   git init
   git add .
   git commit -m "Initial release of PacketFlow Network Diagnostic Engine"
   git remote add origin https://github.com/<your-username>/PacketFlow.git
   git branch -M main
   git push -u origin main
   ```

2. **Import into Vercel**:
   - Go to [vercel.com](https://vercel.com) and log in.
   - Click **"Add New..."** &rarr; **"Project"**.
   - Select your `PacketFlow` GitHub repository.

3. **Configure Project**:
   - **Framework Preset**: Next.js (automatically detected).
   - **Root Directory**: `./` (default).
   - **Build Command**: `next build` (default).
   - **Output Directory**: `.next` (default).
   - *No Environment Variables required.*

4. **Deploy**:
   - Click **"Deploy"**.
   - Vercel will build the project in ~45 seconds and provide you with a live production URL (e.g., `https://packetflow.vercel.app`).

---

### Method B: Deploy via Vercel CLI

```bash
# Install Vercel CLI globally
npm i -g vercel

# Run deployment from the PacketFlow folder
vercel

# Deploy to production
vercel --prod
```

---

## 9. Alignment with Hackathon Judging Criteria

| Criteria | Weight | How PacketFlow Exceeds Expectations |
|---|---|---|
| **Novelty** | **20%** | Differentiates operational faults from cyber attacks automatically. Features an interactive SVG Network Threat Topology graph with animated traffic flows, plus automated defensive firewall & Snort rule synthesis. |
| **Technical Implementation** | **30%** | 100% original TypeScript protocol parser and state machine engine. Implements detection for 12+ attack & fault types, MITRE ATT&CK mapping, and Follow TCP Stream reconstruction with zero native C wrappers. |
| **Security of Solution** | **20%** | Zero code execution guarantees on untrusted packet payloads, strict HTML escaping, client-side offline parsing (zero data leakage), and cryptographic SHA-256 evidence integrity. |
| **Feasibility** | **10%** | Clean 1-command startup (`npm run dev`), pre-loaded 1-click test scenarios, responsive dark/light UI, and native Vercel serverless readiness. |
| **Video Presentation** | **20%** | Full, word-for-word 3-minute video presentation script provided below covering every key feature. |

---

## 10. Winning 3-Minute Video Presentation Script

Use this exact timing and spoken script for your 2 to 5-minute video submission:

### Minute 0:00 - 0:45 &bull; The Problem & System Overview
> *"Hello judges! Welcome to PacketFlow, our Automated Network Packet Analysis and Security Diagnostic Engine built for the Network Track of the Cybersecurity Hackathon.  
> Small offices, research labs, and college departments often face network disruptions. But without a dedicated network engineer, diagnosing packet captures line-by-line in Wireshark is overwhelming. Worse, when connections drop, it's nearly impossible for a beginner to tell whether it's a harmless cable fault or a targeted cyber attack hiding in the exact same traffic.  
> PacketFlow solves this completely: you drop in a PCAP or JSON capture, and our custom engine automatically analyzes the telemetry, differentiates outages from attacks with weighted confidence scores, and outputs human-readable diagnoses with immediate and long-term fixes."*

### Minute 0:45 - 1:30 &bull; Operational Fault Demonstration
> *"Let's test an operational failure. Clicking on our pre-loaded 'TCP Congestion & Outage' scenario, PacketFlow immediately returns a WARNING verdict with a primary classification of BENIGN_FAULT.  
> Notice how the engine identifies a 58% packet loss rate and receiver window exhaustion. It translates this complex TCP zero-window state into plain English for non-experts: 'The receiving computer's buffer is 100% full and asked the sender to pause.'  
> Clicking the finding opens its dedicated Dossier page, citing exact packet frame evidence. Clicking Frame #3 jumps straight into our Deep Packet Inspector, highlighting the zero-window flag."*

### Minute 1:30 - 2:20 &bull; Cyber Attack & Differentiation Demonstration
> *"Now let's switch to an active cyber incident: 'ARP Spoofing & Gateway Hijacking'. The platform instantly shifts to CRITICAL health and MALICIOUS_ATTACK.  
> It isolates the attacker MAC forging unsolicited ARP replies to intercept router traffic, assigning a 98% confidence score. Each attack is mapped to the MITRE ATT&CK framework—here, Technique T1557.002.  
> Next, let's open our Network Threat Topology tab at `/topology`. You can visually see the entire communication graph: the attacker node pulses in red, while hostile traffic vectors are animated across the network."*

### Minute 2:20 - 3:00 &bull; Automated Defense & Forensic Report
> *"PacketFlow doesn't just diagnose—it automates remediation. Under the `/remediation` tab, the engine auto-generates copy-pasteable Linux iptables drop scripts, Snort and Suricata IDS signature rules, and Cisco switch hardening configurations.  
> Finally, navigating to `/report`, PacketFlow generates a print-ready Executive Forensic Audit Report, complete with SHA-256 cryptographic chain-of-custody checksums.  
> In compliance with Rule 3, our parser and detection logic are 100% our own original TypeScript with zero reliance on Wireshark wrappers, and it runs anywhere with zero data leakage. Thank you!"*

---

## License
MIT License &copy; 2026 PacketFlow Contributors &bull; Built for Cybersecurity Hackathon, IIITDM Kancheepuram.
