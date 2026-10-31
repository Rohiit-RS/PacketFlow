/**
 * Custom Security Attacks & Malicious Activity Detection Engine.
 * Detects port scans, IP sweeps, ARP/DNS spoofing, rogue DHCP servers, malformed packets, and data exfiltration.
 */

import { ParsedPacket, Finding, ConversationFlow } from "./types";

export function detectSecurityAttacks(
  packets: ParsedPacket[],
  flows: ConversationFlow[],
  startId = 1
): Finding[] {
  const findings: Finding[] = [];
  let idCounter = startId;
  const nextId = () => `FINDING-${String(idCounter++).padStart(3, "0")}`;

  // 1. Port Scans (SYN stealth, FIN, NULL, XMAS, UDP)
  const synScannerMap = new Map<string, Set<number>>();
  const finScanners = new Map<string, { ports: Set<number>; frames: number[] }>();
  const nullScanners = new Map<string, { ports: Set<number>; frames: number[] }>();
  const xmasScanners = new Map<string, { ports: Set<number>; frames: number[] }>();
  const udpScannerMap = new Map<string, Set<number>>();

  // Also track target destination per scanner
  const scannerTargets = new Map<string, string>();

  for (const pkt of packets) {
    if (pkt.protocol === "TCP" && pkt.source_ip && pkt.destination_ip && pkt.destination_port && pkt.tcp_flags) {
      const src = pkt.source_ip;
      scannerTargets.set(src, pkt.destination_ip);

      const { syn, ack, rst, fin, psh, urg } = pkt.tcp_flags;

      // SYN scan: SYN is set, no ACK
      if (syn && !ack && !rst && !fin) {
        if (!synScannerMap.has(src)) synScannerMap.set(src, new Set());
        synScannerMap.get(src)!.add(pkt.destination_port);
      }

      // NULL scan: no flags set
      if (!syn && !ack && !rst && !fin && !psh && !urg) {
        if (!nullScanners.has(src)) nullScanners.set(src, { ports: new Set(), frames: [] });
        const entry = nullScanners.get(src)!;
        entry.ports.add(pkt.destination_port);
        entry.frames.push(pkt.frame_number);
      }

      // FIN scan: only FIN set
      if (fin && !syn && !ack && !rst && !psh && !urg) {
        if (!finScanners.has(src)) finScanners.set(src, { ports: new Set(), frames: [] });
        const entry = finScanners.get(src)!;
        entry.ports.add(pkt.destination_port);
        entry.frames.push(pkt.frame_number);
      }

      // XMAS scan: FIN + PSH + URG set
      if (fin && psh && urg && !syn && !ack) {
        if (!xmasScanners.has(src)) xmasScanners.set(src, { ports: new Set(), frames: [] });
        const entry = xmasScanners.get(src)!;
        entry.ports.add(pkt.destination_port);
        entry.frames.push(pkt.frame_number);
      }
    } else if (pkt.protocol === "UDP" && pkt.source_ip && pkt.destination_port) {
      if (!udpScannerMap.has(pkt.source_ip)) udpScannerMap.set(pkt.source_ip, new Set());
      udpScannerMap.get(pkt.source_ip)!.add(pkt.destination_port);
    }
  }

  // Check SYN Scan
  for (const [src, ports] of synScannerMap.entries()) {
    if (ports.size >= 5) {
      const dst = scannerTargets.get(src) || "Target Subnet";
      const portArray = Array.from(ports);
      const samplePorts = portArray.slice(0, 6).join(", ") + (portArray.length > 6 ? ` (+${portArray.length - 6} more)` : "");
      
      const evidencePackets = packets
        .filter(p => p.source_ip === src && p.protocol === "TCP" && p.tcp_flags?.syn && !p.tcp_flags?.ack)
        .slice(0, 5)
        .map(p => `Frame #${p.frame_number} TCP [SYN] ${p.source_ip}:${p.source_port} -> ${p.destination_ip}:${p.destination_port}`);

      findings.push({
        id: nextId(),
        category: "ATTACK",
        issue_title: `Stealth TCP SYN Port Scan Detected from ${src}`,
        severity: "HIGH",
        confidence_score: 97,
        plain_language_explanation:
          `A suspicious device (${src}) is systematically knocking on dozens of digital doors (ports) on host ${dst} to find open vulnerabilities, services, or weaknesses to breach.`,
        technical_details: {
          root_cause: `Host ${src} dispatched unsolicited TCP SYN packets across ${ports.size} distinct ports (including ${samplePorts}) without completing standard 3-way handshakes. Characteristic of an automated reconnaissance tool such as Nmap (-sS) or Masscan.`,
          evidence_packets: evidencePackets,
        },
        recommended_remediation: {
          immediate_action:
            `Block source IP ${src} immediately at the perimeter firewall / switch ACL and inspect host ${dst} for unauthorized inbound connections.`,
          long_term_fix:
            "Deploy an Intrusion Detection System (Snort/Suricata) with rate-limiting drop rules and ensure unused listening service ports are disabled.",
        },
        mitre_technique: {
          id: "T1046",
          name: "Network Service Discovery",
          tactic: "Discovery",
          url: "https://attack.mitre.org/techniques/T1046",
        },
        cwe: {
          id: "CWE-200",
          name: "Exposure of Sensitive Information to an Unauthorized Actor",
          url: "https://cwe.mitre.org/data/definitions/200.html",
        },
        remediation_rules: {
          iptables: `iptables -A INPUT -s ${src} -j DROP\niptables -A INPUT -p tcp -m state --state NEW -m limit --limit 10/s --limit-burst 20 -j ACCEPT`,
          snort: `alert tcp ${src} any -> any any (flags:S; threshold:type threshold, track by_src, count 20, seconds 2; msg:"PACKETFLOW: Port Scan from ${src}"; sid:1000001; rev:1;)`,
          cisco: `access-list 100 remark Block Port Scanner ${src}\naccess-list 100 deny ip host ${src} any\naccess-list 100 permit ip any any`,
        },
        affected_ips: [src, dst],
        affected_ports: portArray.slice(0, 10),
      });
    }
  }

  // Check FIN / NULL / XMAS Scans
  for (const [src, data] of xmasScanners.entries()) {
    if (data.ports.size >= 2) {
      findings.push({
        id: nextId(),
        category: "ATTACK",
        issue_title: `Evasive TCP XMAS Scan Detected from ${src}`,
        severity: "HIGH",
        confidence_score: 99,
        plain_language_explanation:
          `An attacker is probing your systems with unusual packet flags (FIN+PSH+URG "lit up like a Christmas tree") designed specifically to sneak past simple firewalls.`,
        technical_details: {
          root_cause: `Detected ${data.ports.size} TCP packets bearing illegal flag combination FIN+PSH+URG against ports ${Array.from(data.ports).slice(0, 5).join(", ")}. Standard RFC 793 stacks drop these on open ports and return RST on closed ports, a fingerprinting tactic used by Nmap (-sX).`,
          evidence_packets: data.frames.slice(0, 4).map(f => `Frame #${f} [TCP FIN+PSH+URG] from ${src}`),
        },
        recommended_remediation: {
          immediate_action: `Isolate host ${src} from the network segment.`,
          long_term_fix: "Configure stateful packet inspection (SPI) firewalls to drop non-standard TCP flag combinations.",
        },
        mitre_technique: {
          id: "T1046",
          name: "Network Service Discovery",
          tactic: "Discovery",
          url: "https://attack.mitre.org/techniques/T1046",
        },
        cwe: {
          id: "CWE-200",
          name: "Exposure of Sensitive Information",
          url: "https://cwe.mitre.org/data/definitions/200.html",
        },
        remediation_rules: {
          iptables: `iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP`,
          snort: `alert tcp ${src} any -> any any (flags:FPU; msg:"PACKETFLOW: Evasive XMAS Scan"; sid:1000002; rev:1;)`,
        },
        affected_ips: [src],
        affected_ports: Array.from(data.ports).slice(0, 5),
      });
    }
  }

  for (const [src, data] of nullScanners.entries()) {
    if (data.ports.size >= 2) {
      findings.push({
        id: nextId(),
        category: "ATTACK",
        issue_title: `TCP NULL Scan Detected from ${src}`,
        severity: "HIGH",
        confidence_score: 98,
        plain_language_explanation:
          `A device is sending naked TCP packets with zero control flags to probe which ports are open while trying to avoid detection.`,
        technical_details: {
          root_cause: `Received packets with zero flags set (Nmap -sN scan) targeting ports ${Array.from(data.ports).slice(0, 4).join(", ")}.`,
          evidence_packets: data.frames.slice(0, 4).map(f => `Frame #${f} [TCP Flags: NONE] from ${src}`),
        },
        recommended_remediation: {
          immediate_action: `Add a drop rule for source IP ${src}.`,
          long_term_fix: "Ensure host firewall blocks stateless packets with no TCP control flags.",
        },
        mitre_technique: {
          id: "T1046",
          name: "Network Service Discovery",
          tactic: "Discovery",
          url: "https://attack.mitre.org/techniques/T1046",
        },
        remediation_rules: {
          iptables: `iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP`,
          snort: `alert tcp ${src} any -> any any (flags:0; msg:"PACKETFLOW: TCP Null Scan Probe"; sid:1000003; rev:1;)`,
        },
        affected_ips: [src],
        affected_ports: Array.from(data.ports).slice(0, 5),
      });
    }
  }

  // 2. IP Sweep / Network Reconnaissance
  const sweepMap = new Map<string, Set<string>>();
  for (const pkt of packets) {
    if (pkt.source_ip && pkt.destination_ip && pkt.source_ip !== pkt.destination_ip) {
      if (!sweepMap.has(pkt.source_ip)) sweepMap.set(pkt.source_ip, new Set());
      sweepMap.get(pkt.source_ip)!.add(pkt.destination_ip);
    }
  }
  for (const [src, targets] of sweepMap.entries()) {
    if (targets.size >= 6) {
      const sampleTargets = Array.from(targets).slice(0, 5).join(", ");
      findings.push({
        id: nextId(),
        category: "ATTACK",
        issue_title: `Internal Subnet IP Sweep / Host Discovery by ${src}`,
        severity: "MEDIUM",
        confidence_score: 92,
        plain_language_explanation:
          `A computer on your network is scanning through every IP address in the office to map out all active laptops, servers, and devices.`,
        technical_details: {
          root_cause: `Host ${src} sequentially sent connection probes (ICMP Echo / TCP handshakes) to ${targets.size} unique internal IP addresses (${sampleTargets}...) in rapid succession. Characteristic of network mapping / lateral movement phase.`,
          evidence_packets: [
            `Probing sequential subnet IPs: ${sampleTargets}`,
            `Source IP: ${src} -> Sweep targets count: ${targets.size}`,
          ],
        },
        recommended_remediation: {
          immediate_action: `Check the physical machine assigned to ${src} for malware or unauthorized scanning software.`,
          long_term_fix: "Implement micro-segmentation / private VLANs to prevent lateral peer-to-peer port sweeps between office workstations.",
        },
        mitre_technique: {
          id: "T1018",
          name: "Remote System Discovery",
          tactic: "Discovery",
          url: "https://attack.mitre.org/techniques/T1018",
        },
        remediation_rules: {
          iptables: `iptables -A INPUT -s ${src} -m limit --limit 10/min -j ACCEPT\niptables -A INPUT -s ${src} -j DROP`,
          cisco: `access-list 105 remark Block Sweep Attacker\naccess-list 105 deny ip host ${src} any`,
        },
        affected_ips: [src, ...Array.from(targets).slice(0, 5)],
      });
    }
  }

  // 3. ARP Spoofing / Poisoning (Man-in-the-Middle)
  const arpReplyCount = new Map<string, { mac: string; frames: number[]; count: number }>();
  for (const pkt of packets) {
    if (pkt.protocol === "ARP" && pkt.arp_opcode === "REPLY" && pkt.arp_sender_ip && pkt.arp_sender_mac) {
      const key = `${pkt.arp_sender_ip}_${pkt.arp_sender_mac}`;
      const entry = arpReplyCount.get(key) || { mac: pkt.arp_sender_mac, frames: [], count: 0 };
      entry.frames.push(pkt.frame_number);
      entry.count++;
      arpReplyCount.set(key, entry);
    }
  }

  // Detect unsolicited Gratuitous ARP flood or gateway hijacking
  const gatewayCandidates = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"];
  for (const [key, val] of arpReplyCount.entries()) {
    const ip = key.split("_")[0];
    const isGateway = gatewayCandidates.includes(ip) || ip.endsWith(".1");
    if (isGateway && val.count >= 3) {
      const evidence = val.frames.slice(0, 4).map(
        f => `Frame #${f} Unsolicited ARP Reply: ${ip} is at ${val.mac}`
      );

      findings.push({
        id: nextId(),
        category: "ATTACK",
        issue_title: `ARP Cache Poisoning / Man-In-The-Middle (MITM) on Gateway ${ip}`,
        severity: "CRITICAL",
        confidence_score: 98,
        plain_language_explanation:
          `A malicious computer (${val.mac}) is pretending to be your internet router/gateway (${ip}). This tricks other computers into sending their passwords, emails, and internet traffic straight to the hacker.`,
        technical_details: {
          root_cause: `Detected ${val.count} unsolicited ARP replies asserting that router IP ${ip} resides at MAC address ${val.mac}. This poisons neighbour ARP caches (arpspoof / ettercap attack) to force traffic interception.`,
          evidence_packets: evidence,
        },
        recommended_remediation: {
          immediate_action:
            `Locate the switch port connecting MAC ${val.mac} and disable it immediately. Clear ARP cache on critical hosts using \`arp -d *\`.`,
          long_term_fix:
            "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on all managed switches so unverified ARP replies are dropped at the hardware level.",
        },
        mitre_technique: {
          id: "T1557.002",
          name: "Adversary-in-the-Middle: ARP Cache Poisoning",
          tactic: "Credential Access / Collection",
          url: "https://attack.mitre.org/techniques/T1557/002",
        },
        cwe: {
          id: "CWE-300",
          name: "Channel Accessible by Non-Endpoint ('Man-in-the-Middle')",
          url: "https://cwe.mitre.org/data/definitions/300.html",
        },
        remediation_rules: {
          iptables: `arptables -A INPUT --source-mac ${val.mac} -j DROP`,
          snort: `alert arp any any -> any any (msg:"PACKETFLOW: Unauthorized Gateway ARP Reply from ${val.mac}"; hwsrc:"${val.mac}"; sid:1000004; rev:1;)`,
          cisco: `! Enable Dynamic ARP Inspection & DHCP Snooping on Cisco Catalyst\nip dhcp snooping\nip dhcp snooping vlan 1\nip arp inspection vlan 1\ninterface GigabitEthernet0/1\n description Gateway Uplink\n ip dhcp snooping trust\n ip arp inspection trust`,
        },
        affected_ips: [ip],
      });
    }
  }

  // 4. DNS Hijacking / Rogue DNS Responses
  const dnsRogueResponses: ParsedPacket[] = [];
  const knownDnsServers = new Set(["192.168.1.1", "192.168.1.254", "10.0.0.1", "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]);
  
  for (const pkt of packets) {
    if (pkt.protocol === "DNS" && pkt.info.includes("response") && pkt.source_ip) {
      // If response comes from unexpected internal workstation
      if (!knownDnsServers.has(pkt.source_ip) && pkt.source_ip.startsWith("192.168.") && !pkt.source_ip.endsWith(".1")) {
        dnsRogueResponses.push(pkt);
      }
    }
  }

  if (dnsRogueResponses.length >= 1) {
    const roguePkt = dnsRogueResponses[0];
    findings.push({
      id: nextId(),
      category: "ATTACK",
      issue_title: `Rogue DNS Server & Hijacking Activity from ${roguePkt.source_ip}`,
      severity: "CRITICAL",
      confidence_score: 94,
      plain_language_explanation:
        `An unauthorized machine (${roguePkt.source_ip}) is answering website domain lookups instead of your official DNS server, likely redirecting users to fake phishing websites.`,
      technical_details: {
        root_cause: `DNS query responses were forged by non-gateway internal host ${roguePkt.source_ip}. This rogue responder intercepts outbound port 53 UDP requests to poison local client domain resolutions.`,
        evidence_packets: dnsRogueResponses.slice(0, 4).map(p => `Frame #${p.frame_number} Rogue DNS Reply for '${p.dns_query || "domain"}' from ${p.source_ip}`),
      },
      recommended_remediation: {
        immediate_action: `Isolate host ${roguePkt.source_ip} from the network immediately.`,
        long_term_fix: "Enforce DNS over HTTPS (DoH) or enforce DNS inspection firewall rules that reject port 53 traffic originating from non-approved internal IPs.",
      },
      mitre_technique: {
        id: "T1584.002",
        name: "Compromise Infrastructure: DNS Server",
        tactic: "Resource Development",
        url: "https://attack.mitre.org/techniques/T1584/002",
      },
      cwe: {
        id: "CWE-346",
        name: "Origin Validation Error",
        url: "https://cwe.mitre.org/data/definitions/346.html",
      },
      remediation_rules: {
        iptables: `iptables -A FORWARD -p udp --dport 53 -s ${roguePkt.source_ip} -j DROP\niptables -A INPUT -p udp --dport 53 -s ${roguePkt.source_ip} -j DROP`,
        cisco: `access-list 120 remark Block Rogue DNS\naccess-list 120 deny udp host ${roguePkt.source_ip} any eq 53\naccess-list 120 permit ip any any`,
      },
      affected_ips: [roguePkt.source_ip || ""].filter(Boolean),
      affected_ports: [53],
    });
  }

  // 5. Rogue DHCP Server
  const dhcpOffers = packets.filter(p => p.protocol === "DHCP" && (p.dhcp_msg_type === "OFFER" || p.dhcp_msg_type === "ACK"));
  const dhcpServers = new Set(dhcpOffers.map(p => p.source_ip || p.dhcp_server_id).filter(Boolean) as string[]);

  if (dhcpServers.size > 1) {
    const serverList = Array.from(dhcpServers);
    const evidence = dhcpOffers.slice(0, 4).map(
      p => `Frame #${p.frame_number} [DHCP ${p.dhcp_msg_type}] from Server IP: ${p.source_ip || p.dhcp_server_id} (Offered: ${p.info})`
    );

    findings.push({
      id: nextId(),
      category: "ATTACK",
      issue_title: `Rogue DHCP Server Detected on Local Network (${serverList.join(", ")})`,
      severity: "CRITICAL",
      confidence_score: 96,
      plain_language_explanation:
        `There are multiple DHCP servers handing out conflicting network settings. A rogue server is attempting to give clients a malicious internet gateway to hijack all internet traffic.`,
      technical_details: {
        root_cause: `Observed conflicting DHCP OFFER/ACK packets originating from multiple independent server IPs (${serverList.join(" vs ")}). Rogue DHCP servers are deployed in Man-In-The-Middle attacks to supply malicious DNS and default router addresses to connecting hosts.`,
        evidence_packets: evidence,
      },
      recommended_remediation: {
        immediate_action:
          `Identify the unauthorized DHCP server physical port (${serverList[1]}) and shut down its network interface.`,
        long_term_fix:
          "Configure DHCP Snooping on all layer 2 switches, marking only the authorized router port as 'Trusted'.",
      },
      mitre_technique: {
        id: "T1557",
        name: "Adversary-in-the-Middle",
        tactic: "Credential Access",
        url: "https://attack.mitre.org/techniques/T1557",
      },
      cwe: {
        id: "CWE-300",
        name: "Channel Accessible by Non-Endpoint",
        url: "https://cwe.mitre.org/data/definitions/300.html",
      },
      remediation_rules: {
        iptables: `iptables -A INPUT -p udp --sport 67 --dport 68 -s ! ${serverList[0] || "192.168.1.1"} -j DROP`,
        cisco: `! Enable Cisco DHCP Snooping\nip dhcp snooping\nip dhcp snooping vlan 1\ninterface GigabitEthernet0/1\n ip dhcp snooping trust`,
      },
      affected_ips: serverList,
      affected_ports: [67, 68],
    });
  }

  // 6. Malformed Packets & Web Exploit Signatures
  const exploitKeywords = ["/bin/sh", "cmd.exe", "UNION SELECT", "OR 1=1", "../../", "<script>", "etc/passwd", "eval("];
  const exploitPackets: { pkt: ParsedPacket; matched: string }[] = [];
  const landAttackPackets: ParsedPacket[] = [];

  for (const pkt of packets) {
    // Land attack: source IP == dest IP and source port == dest port
    if (pkt.source_ip && pkt.destination_ip && pkt.source_ip === pkt.destination_ip && pkt.source_port && pkt.destination_port && pkt.source_port === pkt.destination_port) {
      landAttackPackets.push(pkt);
    }

    // Payload inspection for injection strings
    const payload = (pkt.payload_preview || "") + (pkt.info || "");
    for (const kw of exploitKeywords) {
      if (payload.includes(kw)) {
        exploitPackets.push({ pkt, matched: kw });
        break;
      }
    }
  }

  if (landAttackPackets.length > 0) {
    findings.push({
      id: nextId(),
      category: "ATTACK",
      issue_title: "Malformed Land Attack / Self-Referential Packet Flood",
      severity: "HIGH",
      confidence_score: 99,
      plain_language_explanation:
        "An attacker is transmitting malformed packets where the sender and receiver are spoofed to be the exact same address, causing target systems to loop and crash.",
      technical_details: {
        root_cause: `Identified ${landAttackPackets.length} frames where Source IP equals Destination IP (${landAttackPackets[0].source_ip}:${landAttackPackets[0].source_port}). Classic Land Attack designed to trigger infinite loop lockups on vulnerable TCP/IP stacks.`,
        evidence_packets: landAttackPackets.slice(0, 4).map(p => `Frame #${p.frame_number} Malformed Loop: ${p.source_ip}:${p.source_port} -> ${p.destination_ip}:${p.destination_port}`),
      },
      recommended_remediation: {
        immediate_action: "Enable anti-spoofing egress/ingress filtering (RFC 2827) on the gateway.",
        long_term_fix: "Drop packets whose source address falls into the destination subnet at border routers.",
      },
      mitre_technique: {
        id: "T1498.001",
        name: "Network Denial of Service: Direct Network Flood",
        tactic: "Impact",
        url: "https://attack.mitre.org/techniques/T1498/001",
      },
      cwe: {
        id: "CWE-400",
        name: "Uncontrolled Resource Consumption",
        url: "https://cwe.mitre.org/data/definitions/400.html",
      },
      remediation_rules: {
        iptables: `iptables -A INPUT -s 127.0.0.1 -i eth0 -j DROP\niptables -A INPUT -s ${landAttackPackets[0]?.source_ip} -d ${landAttackPackets[0]?.destination_ip} -j DROP`,
        cisco: `ip access-list extended ANTI_LAND_ATTACK\n deny ip host ${landAttackPackets[0]?.source_ip} host ${landAttackPackets[0]?.destination_ip}\n permit ip any any`,
      },
      affected_ips: [landAttackPackets[0]?.source_ip || ""].filter(Boolean),
    });
  }

  if (exploitPackets.length > 0) {
    const ep = exploitPackets[0];
    findings.push({
      id: nextId(),
      category: "ATTACK",
      issue_title: `Malicious Web Application Payload / Exploit Attempt (${ep.matched})`,
      severity: "CRITICAL",
      confidence_score: 95,
      plain_language_explanation:
        `Network traffic contains explicit malicious attack signatures (such as SQL injection, system shell execution, or directory traversal) targeting an internal server.`,
      technical_details: {
        root_cause: `Detected signature keyword '${ep.matched}' in unencrypted payload data within Frame #${ep.pkt.frame_number} (${ep.pkt.source_ip}:${ep.pkt.source_port} -> ${ep.pkt.destination_ip}:${ep.pkt.destination_port}). Indicates active web exploitation or web shell deployment.`,
        evidence_packets: exploitPackets.slice(0, 4).map(e => `Frame #${e.pkt.frame_number} Pattern [${e.matched}] in ${e.pkt.source_ip} -> ${e.pkt.destination_ip}`),
      },
      recommended_remediation: {
        immediate_action: `Block IP ${ep.pkt.source_ip} and audit server ${ep.pkt.destination_ip} for file system tampering.`,
        long_term_fix: "Deploy a Web Application Firewall (WAF) and sanitize all application database inputs with parameterized SQL queries.",
      },
      mitre_technique: {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        tactic: "Initial Access",
        url: "https://attack.mitre.org/techniques/T1190",
      },
      cwe: {
        id: "CWE-89",
        name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        url: "https://cwe.mitre.org/data/definitions/89.html",
      },
      remediation_rules: {
        iptables: `iptables -A INPUT -s ${ep.pkt.source_ip} -j DROP`,
        snort: `alert tcp ${ep.pkt.source_ip || "any"} any -> any 80 (msg:"PACKETFLOW: Web Exploit Attempt (${ep.matched})"; content:"${ep.matched}"; nocase; sid:1000005; rev:1;)`,
      },
      affected_ips: [ep.pkt.source_ip || "", ep.pkt.destination_ip || ""].filter(Boolean),
    });
  }

  // 7. DNS Tunneling & Data Exfiltration Patterns
  const dnsTunnelQueries: ParsedPacket[] = [];
  for (const pkt of packets) {
    if (pkt.protocol === "DNS" && pkt.dns_query) {
      // Long queries with high entropy / base64 or hex subdomains
      const query = pkt.dns_query;
      const subdomains = query.split(".");
      if (subdomains.length >= 4 || (subdomains[0] && subdomains[0].length > 25)) {
        if (/^[a-zA-Z0-9+/=_-]{20,}$/.test(subdomains[0]) || /^[0-9a-fA-F]{24,}$/.test(subdomains[0])) {
          dnsTunnelQueries.push(pkt);
        }
      }
    }
  }

  if (dnsTunnelQueries.length >= 2) {
    findings.push({
      id: nextId(),
      category: "ATTACK",
      issue_title: "Covert DNS Tunneling & Unauthorized Data Exfiltration",
      severity: "CRITICAL",
      confidence_score: 93,
      plain_language_explanation:
        "A hidden program is smuggling sensitive company data out through fake DNS website lookups to bypass normal firewall blocks.",
      technical_details: {
        root_cause: `Discovered ${dnsTunnelQueries.length} DNS lookups containing high-entropy, base64/hex-encoded payloads in subdomains (e.g. '${dnsTunnelQueries[0].dns_query}'). Typical of DNS tunneling utilities (iodine, dnscat2) used for command-and-control (C2) and data exfiltration.`,
        evidence_packets: dnsTunnelQueries.slice(0, 4).map(p => `Frame #${p.frame_number} Encoded DNS Query: '${p.dns_query}' from ${p.source_ip}`),
      },
      recommended_remediation: {
        immediate_action: `Isolate machine ${dnsTunnelQueries[0].source_ip} and block outbound DNS lookups to the root domain.`,
        long_term_fix: "Deploy DNS RPZ (Response Policy Zones) and filter queries with anomalously long label lengths or high Shannon entropy.",
      },
      mitre_technique: {
        id: "T1071.004",
        name: "Application Layer Protocol: DNS",
        tactic: "Command and Control / Exfiltration",
        url: "https://attack.mitre.org/techniques/T1071/004",
      },
      cwe: {
        id: "CWE-200",
        name: "Exposure of Sensitive Information",
        url: "https://cwe.mitre.org/data/definitions/200.html",
      },
      remediation_rules: {
        iptables: `iptables -A OUTPUT -p udp --dport 53 -m length --length 150:65535 -j DROP`,
        snort: `alert udp any any -> any 53 (msg:"PACKETFLOW: High-Entropy DNS Exfiltration"; dsize:>120; content:"|00 00 10 00 01|"; sid:1000006; rev:1;)`,
      },
      affected_ips: [dnsTunnelQueries[0]?.source_ip || ""].filter(Boolean),
    });
  }

  return findings;
}
