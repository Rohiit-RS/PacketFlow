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

**PacketFlow** solves this challenge by serving as an **Automated Diagnostic & Differentiation Engine**. It ingests technical packet telemetry and raw PCAP captures, applies 100% custom protocol state machines, explicitly distinguishes outages from attacks with weighted confidence scores, and outputs human-readable diagnoses with dual actionable remediations: **Immediate Containment** and **Long-Term Configuration**.

---

## 2. Architecture & Engine Pipeline

```
+-----------------------------------------------------------------------------------+
|                            INGESTION & SAFETY LAYER                              |
|   .pcap / .pcapng binary buffer    |   Wireshark JSON Telemetry   |   1-Click Presets   |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                        SAFE PROTOCOL DECODER & STATE PARSER                       |
|   Bounds-checked binary parser (Ethernet II, 802.1Q, IPv4, IPv6, ARP, TCP, UDP,   |
|   ICMP, DNS, DHCP) with zero-risk payload sanitization (HTML escaping & hex dump) |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                             PARALLEL DETECTION ENGINES                            |
|                                                                                   |
|   [A] OPERATIONAL NETWORK FAULTS          [B] MALICIOUS SECURITY ATTACKS          |
|   - TCP Retransmissions & Packet Loss     - Stealth Port Scans (SYN, FIN, XMAS)  |
|   - Zero Window Buffer Exhaustion         - Subnet IP Sweeps & Reconnaissance     |
|   - Duplicate IP & ARP Collision          - ARP Cache Poisoning (Gateway MITM)    |
|   - MTU Mismatch (ICMP Fragmentation)     - Rogue DNS Responder & Redirection    |
|   - DNS Resolver Failures (NXDOMAIN)      - Rogue DHCP Server Rogue Gateway       |
|   - Abnormal Round-Trip Latency (>250ms)  - Malformed Land Attack & Web Exploits  |
|   - Abrupt TCP RST Aborts                 - Covert DNS Tunneling Exfiltration     |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                         DIFFERENTIATION & CORRELATION ENGINE                      |
|   - Primary Classification: BENIGN_FAULT | MALICIOUS_ATTACK | MIXED | NO_ISSUE     |
|   - Overall Health Status: CRITICAL | WARNING | HEALTHY                           |
|   - Multi-factor Heuristic Confidence Scorer (0 - 100%)                           |
|   - Plain-Language 2-Sentence Executive Summary for Non-Experts                    |
|   - Specific Evidence Packet Citation (Frame #, IP pairs, timestamps, flags)      |
|   - Dual Remediation: Immediate Action + Long-Term Fix                            |
+------------------------------------------+----------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                           OUTPUT & INTERFACE PRESENTATION                         |
|   - Strict JSON Schema API (/api/analyze)                                        |
|   - Swiss Clinical Modern Dashboard (Dark/Light modes)                           |
|   - Deep Frame Inspector & Safe Hex Viewer                                        |
|   - Bidirectional Flow Conversation Matrix                                        |
+-----------------------------------------------------------------------------------+
```

---

## 3. Core Capabilities & Detection Matrix

### A. Network Faults (Operational Issues)
1. **TCP Retransmissions & Loss Rate**: Tracks sequence numbers per flow. Quantifies packet loss percentage and identifies bottlenecked paths.
2. **TCP Window Size Issues (Zero Window Freeze)**: Detects when a receiving endpoint collapses its TCP window to 0, signaling receiver CPU or I/O exhaustion.
3. **Duplicate IP & Addressing Conflicts**: Detects multiple distinct hardware MAC addresses claiming ownership of the identical IP address via ARP broadcasts.
4. **Path MTU Mismatch & Black Hole Routers**: Pinpoints ICMP Type 3 Code 4 (*Destination Unreachable, Fragmentation Needed and DF bit set*) notifications caused by constricted VPN tunnels or VLAN trunks.
5. **DNS Resolver Failures**: Flags anomalous non-zero RCODE responses (NXDOMAIN, SERVFAIL, REFUSED) and query timeout conditions.
6. **Performance & Latency Degradation**: Calculates round-trip-time (RTT) deltas between handshakes and data-acknowledgment sequences, flagging spikes exceeding 250ms.

### B. Security Attacks (Malicious Activity)
1. **Stealth Port Scans**:
   - **SYN Stealth Scan**: Rapid half-open SYN packets across numerous ports without completing the 3-way handshake.
   - **FIN / NULL / XMAS Scans**: Packets with illegal flag combinations (e.g. FIN+PSH+URG or zero flags) engineered to bypass stateless firewalls.
   - **UDP Port Probing**: Systematic probes triggering closed-port ICMP Port Unreachable bursts.
2. **IP Sweeps & Reconnaissance**: Single host systematically pinging and mapping sequential internal IP addresses (`/24`) for active nodes.
3. **ARP Spoofing & MITM Poisoning**: Unsolicited Gratuitous ARP replies asserting ownership of the Default Gateway IP (`192.168.1.1`), diverting traffic through an attacker MAC.
4. **Rogue DNS & Domain Hijacking**: Non-gateway internal hosts forging port 53 UDP replies to redirect corporate users to phishing portals.
5. **Rogue DHCP Server Conflict**: Unauthorized secondary DHCP server offering rogue IP leases, malicious default gateways, and rogue DNS servers.
6. **Traffic Anomalies & Web Exploits**:
   - **Land Attack**: Malformed packets where Source IP equals Destination IP and ports match.
   - **Injection Signatures**: Unencrypted payloads matching SQL injection (`OR 1=1`, `UNION SELECT`), path traversal (`../../etc/passwd`), or command shells (`/bin/sh`, `cmd.exe`).
7. **Covert Data Exfiltration**: DNS Tunneling (unusually long query labels with high Shannon entropy and base32/base64 strings exfiltrating data via TXT/A queries).

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
* **No Hardcoded Secrets**: Fully environment-agnostic with zero external API key requirements.

---

## 6. Built-in Test Captures for Judges

In compliance with the Hackathon guidelines (*"Include a few sample captures in your repository so the judges can run your tool without setting up a network"*), PacketFlow provides **7 pre-synthesized test scenarios** accessible via 1-click in the UI or in the `sample-captures/` folder:

1. **`1_arp_spoofing_mitm.pcap`**: Unsolicited gratuitous ARP poison attack diverting client traffic through an attacker MAC.
2. **`2_syn_port_scan.pcap`**: Nmap-style stealth SYN sweep targeting 15 service ports.
3. **`3_tcp_congestion_outage.pcap`**: 58% TCP retransmission loss with zero-window receiver collapse.
4. **DNS Tunneling & Hijacking**: Covert base64 DNS tunneling coupled with an unauthorized internal DNS responder.
5. **Rogue DHCP Server Conflict**: Colliding DHCP OFFER frames from an unauthorized gateway plus duplicate IP collision.
6. **Path MTU Black Hole**: ICMP Type 3 Code 4 fragmentation needed packets dropped by VPN tunnel MTU constriction.
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
You can test the engine directly from your terminal by posting any PCAP file:
```bash
curl -X POST "http://localhost:3000/api/analyze" \
  --data-binary "@sample-captures/1_arp_spoofing_mitm.pcap" \
  -H "Content-Type: application/octet-stream"
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

1. **Install Vercel CLI**:
   ```bash
   npm i -g vercel
   ```

2. **Login & Deploy**:
   ```bash
   vercel login
   vercel
   ```

3. **Deploy to Production**:
   ```bash
   vercel --prod
   ```

---

## 9. Originality & Open-Source Acknowledgments (Rule 3 Compliance)

In strict accordance with **Rule 3 (Originality)** of the Cybersecurity Hackathon:
* **The detection logic, state correlation algorithms, fault differentiation rules, and confidence scoring models are 100% our own work built from scratch during the hackathon.**
* **We do NOT wrap or invoke `tshark`, `wireshark`, `tcpdump`, or any pre-packaged analyzer.**
* The binary PCAP parser is an original TypeScript implementation parsing byte offsets directly via `DataView`.

### Open-Source Libraries Used:
| Library | Purpose |
|---|---|
| `next` (v15) | React application framework and serverless API routing |
| `react` & `react-dom` (v19) | Modern component rendering |
| `tailwindcss` (v4) | Swiss clinical responsive styling tokens |
| `lucide-react` | Clean icon glyphs for network and security indicators |
| `sonner` | Toast feedback notifications |
| `clsx` & `tailwind-merge` | Conditional CSS class merging |

---

## 10. Demo Video Presentation Outline (2 to 5 Minutes)

For the final submission video, follow this recommended walkthrough:
1. **Introduction (0:00 - 0:45)**:
   - State the problem: Small networks suffer downtime and unnoticed breaches because reading packet captures requires deep protocol expertise.
   - Introduce PacketFlow: An automated diagnostic engine that differentiates harmless operational outages from active cyber attacks.
2. **Operational Fault Demo (0:45 - 1:45)**:
   - Load the "TCP Congestion & Zero Window Outage" or "Path MTU Mismatch" preset.
   - Show how PacketFlow identifies the 58% packet loss rate and explains receiver buffer exhaustion in plain language for beginners.
   - Highlight the dual remediation: immediate switch port audit + long-term TCP buffer tuning.
3. **Cyber Attack & Differentiation Demo (1:45 - 3:00)**:
   - Load "ARP Spoofing & Gateway Hijacking" or "Stealth SYN Port Scan".
   - Show the Health Status (`CRITICAL`), Category (`ATTACK`), and Confidence Score (`98%`).
   - Click cited evidence packets to jump straight into the Deep Frame Inspector.
4. **Under the Hood & Safe Parsing (3:00 - 3:45)**:
   - Show how the pure TypeScript binary parser safely ingests `.pcap` files without server data leakage.
   - Show the strict schema JSON output (`/api/analyze`).
5. **Conclusion & Impact (3:45 - 4:30)**:
   - Summary of impact for small teams, labs, and campus networks.

---

## License
MIT License &copy; 2026 PacketFlow Contributors &bull; Built for Cybersecurity Hackathon, IIITDM Kancheepuram.
