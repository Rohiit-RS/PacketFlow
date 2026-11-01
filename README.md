# PacketFlow

**One capture across every layer, and the threats no single tool could see.**

Network Track &bull; 24-Hour Cybersecurity Hackathon &bull; IIITDM Kancheepuram: *"Diagnosing Network Problems from Packet Captures."*

- **Live app:** https://packetflow.vercel.app *(or deploy locally on port 3000)*
- **Demo video:** [Watch the 3-Minute Video Walkthrough](https://youtu.be/demo-packetflow)
- **Try it without setup:** The home page has 1-click evaluation scenarios (ARP Cache Poisoning, Stealth SYN Scan, Covert DNS Tunneling & DGA, TCP Congestion & Outage, Rogue DHCP & IP Collision, MTU Black Hole, and Clean Baseline). All capture data is self-contained.

---

## The problem

Small offices, university computer labs, and campus departments depend on their local networks every day. When the network becomes sluggish, drops connections, or behaves erratically, the traditional diagnostic procedure requires opening a packet capture (`.pcap`) and inspecting raw hex frames line-by-line.

- **Recall & Isolation fail.** Non-expert users only notice *"the internet is down"*, without knowing whether the failure is at Layer 2 (ARP), Layer 3 (IP/MTU), Layer 4 (TCP), or Layer 7 (DNS/App).
- **Wireshark overwhelms.** Sifting through 10,000 hex frames manually is impossible for non-expert administrators under pressure.
- **Harms fall between layers (The Crucial Blind Spot):**
  - An attacker launches an **ARP Cache Poisoning** or a **TCP SYN Flood**. The rogue host intercepts traffic and saturates the link.
  - Intermediate switches drop packets, and endpoints begin aggressively retransmitting, triggering a severe **TCP Retransmission Storm** and **RTT Latency Spikes**.
  - A naive diagnostic tool alerts on *"Bad Ethernet Cable / Switch Bufferbloat"*, treating it as an independent hardware failure while the active hacker remains completely invisible!
- **Remediation is disconnected.** Diagnostic outputs leave administrators stranded with error codes rather than ready-to-run firewall drop rules, IDS signatures, or router configuration commands.

---

## The solution

PacketFlow is an automated network packet analysis and security diagnostic engine built from the ground up in pure TypeScript.

1. **Ingest anything.** Drag-and-drop any binary `.pcap`, `.pcapng`, or JSON telemetry stream:
   - Client-side, memory-safe binary parser with strict byte bounds checking;
   - Parses Ethernet II, IPv4, TCP (flags, sequence, window), UDP, ICMP, ARP, DNS, and DHCP;
   - Treats payloads strictly as inert data (zero `eval`, HTML-sanitized, non-printable bytes converted to ASCII dots).
2. **Dual-Bucket Categorization.** Findings are strictly partitioned into:
   - **Network Faults (Operational Issues):** TCP retransmissions, resets, out-of-order delivery, zero-window freezes, duplicate IPs, ARP conflicts, MTU black holes, DNS failures, and RTT latency spikes.
   - **Security Attacks (Malicious Activity):** SYN/FIN/NULL/XMAS/UDP port scans, IP subnet sweeps, ARP spoofing, rogue DNS, rogue DHCP, Land attacks, SQL injection/web shells, DNS tunneling, and algorithmic DGA malware C2 beacons.
3. **Cross-Layer Causal Inference (Our USP & Core Innovation):** Evaluates protocol causality across layers 2, 3, 4, and 7:
   - Discovers when lower-layer attacks induce layer-4 TCP performance degradation;
   - Explicitly tags the operational fault as an **`⚡ Induced Collateral Symptom`**;
   - Points back to the primary **`🎯 Root Cause Driver`**;
   - Synthesizes a chronological **Incident Kill-Chain Timeline** (*Phase 1: Reconnaissance &rarr; Phase 2: Exploitation &rarr; Phase 3: Induced Operational Degradation*).
4. **Interactive Network Threat Topology.** Real-time SVG host communication graph with animated traffic vectors, pulsing hostile halos, and per-host inspection drawers.
5. **Wireshark-Grade Deep Packet Inspector.**
   - **Click-to-Filter:** Clicking any Source IP, Destination IP, or Protocol cell instantly adds it as an active filter chip with 1-click removal;
   - **16-Byte Hex Dump Grid:** Wireshark-aligned memory offsets, hex bytes, and printable ASCII characters with one-click copy;
   - **Follow TCP Stream:** Reconstructs bidirectional conversational client-server payloads with syntax highlighting.
6. **Automated Remediation Generator.**
   - **Dynamic Interface Binding:** Select or type your host network interface (`eth0`, `ens33`, `wlan0`, `br0`) to instantly rewrite all generated scripts;
   - **Finding Checklist Toggles:** Selectively include or exclude specific findings from the generated defense bundle;
   - **Multi-Format Synthesis:** Ready-to-execute Linux `iptables` scripts (`remediation.sh`), Snort/Suricata IDS rules (`.rules`), and Cisco IOS switch hardening;
   - **Dry-Run Console Simulator:** Simulated Linux shell terminal previewing realistic kernel execution traces.
7. **Forensic Audit & Cryptographic Chain of Custody.** Print/PDF-ready incident whitepapers carrying cryptographic **SHA-256** and **MD5** capture checksums, radial threat dials, and MITRE ATT&CK matrix mappings.
8. **Strict Output JSON Schema & 1-Click Export.** Fully compliant with the hackathon diagnostic schema (`summary` + `findings[]`) and includes **1-click export of binary `.pcap` files** to open directly in Wireshark.

---

## Architecture

```
Browser (Dashboard / Findings / Packets / Topology / Remediation / Report / Docs, Light + Dark Theme)
   │   Next.js 15 App Router: Server Components, Client State Machine, App API Routes
   │   Pure TypeScript Ingestion Engine: PCAP & PCAPNG binary parser (bounds-checked, zero eval)
   ├── lib/engine/faultDetector.ts  ── Operational Faults: Retransmissions, Zero-Window, PMTUD, OOO, RST storms
   ├── lib/engine/attackDetector.ts ── Security Attacks: Port Scans, Sweeps, ARP MITM, Rogue DNS/DHCP, DGA, Exfiltration
   ├── lib/engine/differentiator.ts ── Causal Inference & Correlation: Induced Collateral Damage vs Root Cause Driver
   ├── lib/engine/pcapWriter.ts     ── Synthetic RFC-Compliant Binary PCAP Generator (Wireshark-ready export)
   └── app/api/analyze/route.ts     ── Programmatic REST Endpoint (Strict Evaluation JSON Schema)
```

- **Zero Native Wrappers:** 100% original TypeScript protocol parser and diagnostic state machines. Zero dependencies on Wireshark CLI, `tshark`, or `tcpdump` binary subprocesses (fully compliant with Rule 3).
- **Client-Side Sandbox:** Binary parsing executes in local browser memory. Confidential network captures never leave the local environment unless explicitly submitted to an API endpoint.
- **Cryptographic Evidence Integrity:** Every ingested frame sequence generates deterministic SHA-256 and MD5 forensic checksums for incident chain of custody.

---

## Key folders

| Path | What it is |
|---|---|
| `lib/engine/` | Core diagnostic engine: `faultDetector.ts`, `attackDetector.ts`, `differentiator.ts`, `pcapParser.ts`, `pcapWriter.ts`, `types.ts` |
| `lib/samples/` | 7 realistic packet captures: ARP MITM, SYN Scan, DNS Tunneling & DGA, TCP Congestion, Rogue DHCP, MTU Black Hole, and Clean Baseline |
| `lib/context/` | `CaptureContext.tsx`: Client-side ingestion state, session persistence, and scenario loading |
| `lib/utils/` | Forensic utilities: `hash.ts` (SHA-256 and MD5 implementation), `formatters.ts` (byte & timestamp formatting) |
| `components/` | Modular UI components: `PacketInspector.tsx`, `NetworkTopology.tsx`, `RemediationGenerator.tsx`, `IncidentTimeline.tsx`, `ForensicReport.tsx` |
| `app/` | Multi-page App Router architecture: `/`, `/findings`, `/findings/[id]`, `/packets`, `/flows`, `/topology`, `/remediation`, `/report`, `/schema`, `/docs`, `/api/analyze` |

---

## Run it locally

**Requirements:** Node 18+ (tested on Node 20 and Node 22).

```bash
# 1. Install dependencies
npm install

# 2. Start development server
npm run dev
# App will be live at http://localhost:3000

# 3. Or create an optimized production build
npm run build
npm run start
```

### Try the Programmatic API (`/api/analyze`)

You can test the diagnostic engine via `curl` or HTTP client by posting raw JSON telemetry or multipart PCAP files:

```bash
curl -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '[
    { "frame_number": 1, "timestamp": 1730419200.0, "length": 60, "protocol": "ARP", "arp_opcode": "REPLY", "arp_sender_ip": "192.168.1.1", "arp_sender_mac": "00:0c:29:8a:4f:1b", "info": "192.168.1.1 is at 00:0c:29:8a:4f:1b" },
    { "frame_number": 2, "timestamp": 1730419200.05, "length": 60, "protocol": "ARP", "arp_opcode": "REPLY", "arp_sender_ip": "192.168.1.1", "arp_sender_mac": "00:0c:29:8a:4f:1b", "info": "192.168.1.1 is at 00:0c:29:8a:4f:1b" },
    { "frame_number": 3, "timestamp": 1730419200.1, "length": 60, "protocol": "ARP", "arp_opcode": "REPLY", "arp_sender_ip": "192.168.1.1", "arp_sender_mac": "00:0c:29:8a:4f:1b", "info": "192.168.1.1 is at 00:0c:29:8a:4f:1b" }
  ]'
```

---

## Deploy (Vercel)

PacketFlow is built on standard Next.js 15 and is 100% serverless-ready for instant Vercel deployment:

### Option A: Via GitHub (Recommended)
1. Push your repository to GitHub:
   ```bash
   git remote add origin https://github.com/<your-username>/PacketFlow.git
   git branch -M main
   git push -u origin main
   ```
2. Open [vercel.com](https://vercel.com) &rarr; **"Add New..."** &rarr; **"Project"**.
3. Import your **`PacketFlow`** repository.
4. Leave all settings as default (Framework: Next.js, Build: `next build`, Output: `.next`).
5. Click **"Deploy"**. The app will be live globally in ~60 seconds.

### Option B: Via Vercel CLI
```bash
npm i -g vercel
vercel
vercel --prod
```

---

## Safety and input bounds

- **Strict Buffer Bounds:** Every binary slice of an ingested PCAP buffer is verified against the buffer's total byte length prior to reading, eliminating out-of-bounds reads and memory overflows.
- **Data-Only Handling:** Raw packet payloads are treated strictly as read-only binary data. Control characters and HTML script tags are sanitized and non-printable bytes are mapped to ASCII dots, preventing XSS and shell injection.
- **Sandboxed Execution:** Binary parsing executes directly in the browser runtime. Confidential corporate packets never leave the customer's local memory unless explicitly submitted to an on-premise REST endpoint.
- **Explainable Findings:** Explanations are written in plain, beginner-friendly language understandable by a small-office user without requiring a dedicated security team.

---

## Libraries and APIs used (disclosure)

- **Framework and UI:**
  - Next.js 15 (App Router), React 19, TypeScript
  - Tailwind CSS v4
  - Lucide React (forensic & network icons), Sonner (notification toasts)
  - Hanken Grotesk via `next/font`
- **Engine (100% Original Code):**
  - Pure TypeScript binary PCAP / PCAPNG parser (`lib/engine/pcapParser.ts`)
  - Deterministic operational fault state machine (`lib/engine/faultDetector.ts`)
  - Malicious security intrusion detector (`lib/engine/attackDetector.ts`)
  - Cross-layer causal inference & differentiator engine (`lib/engine/differentiator.ts`)
  - Synthetic RFC-compliant binary PCAP generator (`lib/engine/pcapWriter.ts`)
  - Cryptographic SHA-256 and MD5 hashing (`lib/utils/hash.ts`)
- **Dev & Tooling:**
  - Node.js, npm, Git

---

## Protocol & standards references

Every heuristic and detection rule is grounded in official RFC standards and MITRE ATT&CK techniques:

- **RFC Standards:**
  - **RFC 793:** Transmission Control Protocol (TCP) state machine, sequence tracking, window sizing, and out-of-order reassembly.
  - **RFC 826:** Address Resolution Protocol (ARP) gratuitous reply inspection and duplicate IP collision detection.
  - **RFC 1035:** Domain Name System (DNS) query/response decoding, RCODE parsing, and label compression.
  - **RFC 2131:** Dynamic Host Configuration Protocol (DHCP) rogue OFFER/ACK interception and gateway fraud.
  - **RFC 1191:** Path MTU Discovery (PMTUD) and ICMP Type 3 Code 4 fragmentation needed black hole analysis.
  - **RFC 2827 (BCP 38):** Network ingress anti-spoofing and self-referential Land attack loops.
- **MITRE ATT&CK Framework Mappings:**
  - **T1046:** Network Service Discovery (SYN stealth, FIN, NULL, XMAS, UDP port scanning)
  - **T1018:** Remote System Discovery (Internal subnet IP sweeps)
  - **T1557.002:** Adversary-in-the-Middle: ARP Cache Poisoning
  - **T1584.002:** Compromise Infrastructure: DNS Server (Rogue DNS responders)
  - **T1557:** Adversary-in-the-Middle (Rogue DHCP servers)
  - **T1190:** Exploit Public-Facing Application (SQL injection & web shell payload patterns)
  - **T1071.004:** Application Layer Protocol: DNS (High-entropy covert DNS tunneling)
  - **T1568.002:** Dynamic Resolution: Domain Generation Algorithms (DGA malware C2 beacons)
- **CWE Mappings:**
  - **CWE-200:** Exposure of Sensitive Information
  - **CWE-300:** Channel Accessible by Non-Endpoint (Man-in-the-Middle)
  - **CWE-346:** Origin Validation Error
  - **CWE-400:** Uncontrolled Resource Consumption
  - **CWE-436:** Interpretation Conflict (Duplicate IP / Routing conflict)
  - **CWE-89:** SQL Injection

---

## Alignment with hackathon judging criteria

| Criteria | Weight | How PacketFlow Exceeds Expectations |
|---|---|---|
| **Novelty** | **20%** | Features **Cross-Layer Causal Inference** (discovering when attacks induce collateral operational faults). Real-time SVG Network Threat Topology graph with animated vectors, plus automated firewall & Snort rule synthesis. |
| **Technical Implementation** | **30%** | 100% original TypeScript protocol parser and state machine engine. Implements detection for 14+ attack & fault types, MITRE ATT&CK mapping, and Follow TCP Stream reconstruction with zero native C/tshark wrappers. |
| **Security of Solution** | **20%** | Zero code execution guarantees on untrusted packet payloads, strict HTML escaping, client-side offline parsing (zero data leakage), and cryptographic SHA-256 evidence integrity. |
| **Feasibility** | **10%** | Clean 1-command startup (`npm run dev`), pre-loaded 1-click test scenarios, responsive dark/light UI, and native Vercel serverless readiness. |
| **Video Presentation** | **20%** | Full, word-for-word 3-minute video presentation script provided below covering every key feature. |

---

## Winning 3-minute video presentation script

Use this exact timing and spoken script for your video submission:

### Minute 0:00 - 0:45 &bull; The Problem & System Overview
> *"Hello judges! Welcome to PacketFlow, our Automated Network Packet Analysis and Security Diagnostic Engine built for the Network Track of the Cybersecurity Hackathon.  
> Small offices, research labs, and college departments often face network disruptions. But without a dedicated network engineer, diagnosing packet captures line-by-line in Wireshark is overwhelming. Worse, when connections drop, it's nearly impossible for a beginner to tell whether it's a harmless cable fault or a targeted cyber attack hiding in the exact same traffic.  
> PacketFlow solves this completely: you drop in a PCAP or JSON capture, and our custom engine automatically analyzes the telemetry, differentiates outages from attacks with weighted confidence scores, and outputs human-readable diagnoses with immediate and long-term fixes."*

### Minute 0:45 - 1:30 &bull; Operational Fault Demonstration
> *"Let's test an operational failure. Clicking on our pre-loaded 'TCP Congestion & Outage' scenario, PacketFlow immediately returns a WARNING verdict with a primary classification of BENIGN_FAULT.  
> Notice how the engine identifies a 58% packet loss rate and receiver window exhaustion. It translates this complex TCP zero-window state into plain English for non-experts: 'The receiving computer's buffer is 100% full and asked the sender to pause.'  
> Clicking the finding opens its dedicated Dossier page, citing exact packet frame evidence. Clicking Frame #3 jumps straight into our Deep Packet Inspector, highlighting the zero-window flag."*

### Minute 1:30 - 2:20 &bull; Cyber Attack & Causal Differentiation Demonstration
> *"Now let's switch to an active cyber incident: 'ARP Spoofing & Gateway Hijacking'. The platform instantly shifts to CRITICAL health and MALICIOUS_ATTACK.  
> It isolates the attacker MAC forging unsolicited ARP replies to intercept router traffic, assigning a 98% confidence score. Each attack is mapped to the MITRE ATT&CK framework—here, Technique T1557.002.  
> Crucially, look at our Cross-Layer Causal Correlation: the engine notices that the ARP attack caused lower-layer packet loss, which triggered a storm of TCP retransmissions. It explicitly flags the retransmissions as an Induced Collateral Symptom caused by the primary attack!  
> Next, let's open our Network Threat Topology tab at `/topology`. You can visually see the entire communication graph: the attacker node pulses in red, while hostile traffic vectors are animated across the network."*

### Minute 2:20 - 3:00 &bull; Automated Defense & Forensic Report
> *"PacketFlow doesn't just diagnose—it automates remediation. Under the `/remediation` tab, the engine auto-generates copy-pasteable Linux iptables drop scripts, Snort and Suricata IDS signature rules, and Cisco switch hardening configurations. You can select your network interface, toggle findings, and even test them in our live dry-run shell simulator.  
> Finally, navigating to `/report`, PacketFlow generates a print-ready Executive Forensic Audit Report, complete with SHA-256 cryptographic chain-of-custody checksums.  
> In compliance with Rule 3, our parser and detection logic are 100% our own original TypeScript with zero reliance on Wireshark wrappers, and it runs anywhere with zero data leakage. Thank you!"*

---

## License

MIT License &copy; 2026 PacketFlow Contributors &bull; Built for Cybersecurity Hackathon, IIITDM Kancheepuram.
