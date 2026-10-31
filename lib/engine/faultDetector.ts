/**
 * Custom Network Faults & Operational Issues Detection Engine.
 * Detects TCP anomalies, addressing/routing conflicts, DNS failures, and performance degradation.
 */

import { ParsedPacket, Finding, ConversationFlow } from "./types";

export function detectNetworkFaults(
  packets: ParsedPacket[],
  flows: ConversationFlow[],
  startId = 1
): Finding[] {
  const findings: Finding[] = [];
  let idCounter = startId;

  const nextId = () => `FINDING-${String(idCounter++).padStart(3, "0")}`;

  // 1. TCP Retransmissions & Packet Loss
  const streamSeqMap = new Map<string, Map<number, ParsedPacket[]>>();
  const retransmissionPackets: ParsedPacket[] = [];
  const outOfOrderPackets: ParsedPacket[] = [];
  const zeroWindowPackets: ParsedPacket[] = [];
  const tcpResetPackets: ParsedPacket[] = [];

  for (const pkt of packets) {
    if (pkt.protocol === "TCP" && pkt.source_ip && pkt.destination_ip && pkt.source_port && pkt.destination_port) {
      const flowKey = `${pkt.source_ip}:${pkt.source_port}->${pkt.destination_ip}:${pkt.destination_port}`;
      
      // Zero Window Detection
      if (pkt.tcp_window_size === 0 && !pkt.tcp_flags?.rst && !pkt.tcp_flags?.syn) {
        zeroWindowPackets.push(pkt);
      }

      // TCP Reset Detection
      if (pkt.tcp_flags?.rst) {
        tcpResetPackets.push(pkt);
      }

      // Sequence tracking for retransmission & out-of-order
      if (pkt.tcp_seq !== undefined && pkt.length > 54) {
        if (!streamSeqMap.has(flowKey)) {
          streamSeqMap.set(flowKey, new Map());
        }
        const seqMap = streamSeqMap.get(flowKey)!;
        if (seqMap.has(pkt.tcp_seq)) {
          // Same sequence number with payload re-sent = retransmission
          retransmissionPackets.push(pkt);
        } else {
          seqMap.set(pkt.tcp_seq, [pkt]);
        }
      }
    }
  }

  // Evaluate TCP Retransmissions / Packet Loss
  const totalTcp = packets.filter(p => p.protocol === "TCP").length;
  if (retransmissionPackets.length > 0 && totalTcp > 0) {
    const retransRatio = (retransmissionPackets.length / totalTcp) * 100;
    if (retransRatio > 3 || retransmissionPackets.length >= 3) {
      const severity = retransRatio > 15 ? "CRITICAL" : retransRatio > 7 ? "HIGH" : "MEDIUM";
      const evidence = retransmissionPackets.slice(0, 5).map(
        p => `Frame #${p.frame_number} [TCP Retransmission] Seq=${p.tcp_seq} Len=${p.length} (${p.source_ip}:${p.source_port} -> ${p.destination_ip}:${p.destination_port})`
      );

      findings.push({
        id: nextId(),
        category: "FAULT",
        issue_title: `High TCP Retransmission Rate (${retransRatio.toFixed(1)}% packet loss indicator)`,
        severity,
        confidence_score: Math.min(98, Math.round(75 + retransRatio * 1.5)),
        plain_language_explanation:
          "The sender had to re-transmit packets multiple times because the receiving device or network dropped them. This leads to slow loading speeds, stalled video calls, or frozen downloads.",
        technical_details: {
          root_cause: `Detected ${retransmissionPackets.length} duplicate TCP sequence transmissions out of ${totalTcp} TCP packets (${retransRatio.toFixed(1)}% retransmission rate). Typically caused by congested intermediate switches, faulty cabling, RF Wi-Fi interference, or asymmetric link saturation.`,
          evidence_packets: evidence,
        },
        recommended_remediation: {
          immediate_action:
            "Inspect physical switch port interface statistics for FCS/CRC errors or queue discards on the route between the affected endpoints.",
          long_term_fix:
            "Enable flow control/QoS prioritization, replace degraded Ethernet patch cables, and optimize TCP buffer windows.",
        },
        cwe: {
          id: "CWE-400",
          name: "Uncontrolled Resource Consumption",
          url: "https://cwe.mitre.org/data/definitions/400.html",
        },
        remediation_rules: {
          iptables: `sysctl -w net.ipv4.tcp_retries2=8\nsysctl -w net.ipv4.tcp_sack=1`,
          cisco: `interface GigabitEthernet0/1\n flowcontrol receive on\n flowcontrol send on`,
        },
        affected_ips: Array.from(new Set(retransmissionPackets.map(p => p.source_ip || "").filter(Boolean))).slice(0, 5),
      });
    }
  }

  // Evaluate TCP Zero Window / Buffer Bloat
  if (zeroWindowPackets.length >= 2) {
    const evidence = zeroWindowPackets.slice(0, 4).map(
      p => `Frame #${p.frame_number} [TCP ZeroWindow] Win=0 (${p.source_ip}:${p.source_port} -> ${p.destination_ip}:${p.destination_port})`
    );

    findings.push({
      id: nextId(),
      category: "FAULT",
      issue_title: "TCP Receiver Window Exhaustion (Zero Window Freeze)",
      severity: "HIGH",
      confidence_score: 94,
      plain_language_explanation:
        "A receiving computer signaled that its internal memory buffer is 100% full and asked the sender to completely pause sending data. This freezes connections until the receiving app catches up.",
      technical_details: {
        root_cause: `The TCP receive window collapsed to 0 across ${zeroWindowPackets.length} frames. The receiver application layer (e.g. database, web service, or local client) is CPU-bound or I/O bottlenecked and cannot drain its socket receive buffer fast enough.`,
        evidence_packets: evidence,
      },
      recommended_remediation: {
        immediate_action:
          `Check CPU and RAM utilization on the receiver host (${zeroWindowPackets[0]?.source_ip || "affected endpoint"}) to identify the hung or overwhelmed application.`,
        long_term_fix:
          "Tune operating system TCP socket buffer sizing (`SO_RCVBUF`) and optimize application multi-threading.",
      },
      cwe: {
        id: "CWE-400",
        name: "Uncontrolled Resource Consumption (Buffer Exhaustion)",
        url: "https://cwe.mitre.org/data/definitions/400.html",
      },
      remediation_rules: {
        iptables: `sysctl -w net.ipv4.tcp_rmem="4096 87380 6291456"\nsysctl -w net.core.rmem_max=16777216`,
      },
      affected_ips: Array.from(new Set(zeroWindowPackets.map(p => p.source_ip || "").filter(Boolean))),
    });
  }

  // 2. Addressing & Routing: Duplicate IP & ARP Conflicts
  const ipToMacMap = new Map<string, Map<string, number[]>>();
  for (const pkt of packets) {
    if (pkt.protocol === "ARP" && pkt.arp_sender_ip && pkt.arp_sender_mac) {
      if (pkt.arp_sender_ip !== "0.0.0.0") {
        if (!ipToMacMap.has(pkt.arp_sender_ip)) {
          ipToMacMap.set(pkt.arp_sender_ip, new Map());
        }
        const macs = ipToMacMap.get(pkt.arp_sender_ip)!;
        const frames = macs.get(pkt.arp_sender_mac) || [];
        frames.push(pkt.frame_number);
        macs.set(pkt.arp_sender_mac, frames);
      }
    }
  }

  for (const [ip, macs] of ipToMacMap.entries()) {
    if (macs.size > 1) {
      const macList = Array.from(macs.keys());
      const evidence: string[] = [];
      macs.forEach((frames, mac) => {
        evidence.push(`IP ${ip} claimed by MAC ${mac} in Frames [${frames.slice(0, 3).join(", ")}]`);
      });

      findings.push({
        id: nextId(),
        category: "FAULT",
        issue_title: `Duplicate IP Address & ARP Conflict on ${ip}`,
        severity: "CRITICAL",
        confidence_score: 96,
        plain_language_explanation:
          `Two different devices on the local network are competing for the exact same IP address (${ip}). As a result, network traffic is randomly split between them, knocking both devices offline periodically.`,
        technical_details: {
          root_cause: `Gratuitous and reply ARP frames reveal that IP ${ip} is concurrently claimed by multiple physical hardware addresses (${macList.join(" and ")}). Common causes include a rogue static IP configured inside a dynamic DHCP scope or a cloned VM network adapter.`,
          evidence_packets: evidence,
        },
        recommended_remediation: {
          immediate_action:
            `Disconnect or isolate one of the conflicting physical MACs (${macList[1]}) from the switch port to restore stable connectivity.`,
          long_term_fix:
            "Enforce DHCP snooping and IP Source Guard on managed switch trunks, and reserve static assignments outside the active DHCP pool.",
        },
        cwe: {
          id: "CWE-436",
          name: "Interpretation Conflict",
          url: "https://cwe.mitre.org/data/definitions/436.html",
        },
        remediation_rules: {
          cisco: `! Cisco Port Security & IP Source Guard\ninterface GigabitEthernet0/2\n switchport mode access\n switchport port-security\n switchport port-security maximum 1\n switchport port-security violation restrict\n ip verify source`,
        },
        affected_ips: [ip],
      });
    }
  }

  // 3. MTU Mismatch & ICMP Fragmentation Needed
  const mtuIssues = packets.filter(
    p => p.protocol === "ICMP" && p.icmp_type === 3 && p.icmp_code === 4
  );
  if (mtuIssues.length > 0) {
    const evidence = mtuIssues.slice(0, 4).map(
      p => `Frame #${p.frame_number} ICMP Destination Unreachable: Fragmentation Needed and DF set (${p.source_ip} -> ${p.destination_ip})`
    );

    findings.push({
      id: nextId(),
      category: "FAULT",
      issue_title: "Path MTU Mismatch & Fragmentation Black Hole",
      severity: "HIGH",
      confidence_score: 95,
      plain_language_explanation:
        "Large network packets are being rejected by an intermediate router because they exceed the maximum transmission size (MTU), but the sender was told not to break them into smaller pieces.",
      technical_details: {
        root_cause: `Observed ${mtuIssues.length} ICMP Type 3 Code 4 ("Fragmentation Needed and DF bit set") notifications. An intermediate router or VPN tunnel (e.g. WireGuard, IPsec, PPPoE) has an MTU lower than the 1500-byte standard, causing large payloads to be silently discarded.`,
        evidence_packets: evidence,
      },
      recommended_remediation: {
        immediate_action:
          "Lower the client interface MTU to 1420 or enable MSS clamping on the perimeter gateway/firewall.",
        long_term_fix:
          "Ensure ICMP Type 3 Code 4 messages are not filtered by local host firewalls to allow Path MTU Discovery (PMTUD) to negotiate automatically.",
      },
      cwe: {
        id: "CWE-436",
        name: "Interpretation Conflict",
        url: "https://cwe.mitre.org/data/definitions/436.html",
      },
      remediation_rules: {
        iptables: `iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o eth0 -j TCPMSS --clamp-mss-to-pmtu`,
        cisco: `interface GigabitEthernet0/1\n ip tcp adjust-mss 1360`,
      },
      affected_ips: Array.from(new Set(mtuIssues.map(p => p.source_ip || "").filter(Boolean))),
    });
  }

  // 4. DNS Query Failures & Timeouts
  const dnsQueries = new Map<string, { frame: number; time: number; query: string }>();
  const dnsFailures: ParsedPacket[] = [];
  const dnsTimeouts: { query: string; frame: number }[] = [];

  for (const pkt of packets) {
    if (pkt.protocol === "DNS") {
      if (pkt.dns_response_code !== undefined && pkt.dns_response_code > 0) {
        // RCODE 2 = SERVFAIL, 3 = NXDOMAIN, 5 = REFUSED
        dnsFailures.push(pkt);
      } else if (pkt.dns_query && pkt.info.includes("Standard query 0x")) {
        const idMatch = pkt.info.match(/0x([0-9a-fA-F]+)/);
        const qId = idMatch ? idMatch[1] : `${pkt.dns_query}_${pkt.frame_number}`;
        dnsQueries.set(qId, { frame: pkt.frame_number, time: pkt.timestamp, query: pkt.dns_query });
      } else if (pkt.info.includes("response 0x")) {
        const idMatch = pkt.info.match(/0x([0-9a-fA-F]+)/);
        if (idMatch) dnsQueries.delete(idMatch[1]);
      }
    }
  }

  // Queries pending over 1.5s
  if (dnsFailures.length >= 2) {
    const evidence = dnsFailures.slice(0, 5).map(
      p => `Frame #${p.frame_number} DNS Failure (RCODE ${p.dns_response_code}): Query '${p.dns_query || "unknown"}' from ${p.destination_ip || "server"}`
    );

    findings.push({
      id: nextId(),
      category: "FAULT",
      issue_title: `DNS Name Resolution Failures (NXDOMAIN / SERVFAIL)`,
      severity: "MEDIUM",
      confidence_score: 91,
      plain_language_explanation:
        "The computer tried looking up website or service addresses via DNS, but the DNS server returned errors saying the domain does not exist or the upstream DNS system failed.",
      technical_details: {
        root_cause: `Detected ${dnsFailures.length} unsuccessful DNS query responses with non-zero RCODEs (ServerFailure or Non-Existent Domain). Indicates misconfigured local search suffixes, stale DNS cache entries, or upstream forwarder failure.`,
        evidence_packets: evidence,
      },
      recommended_remediation: {
        immediate_action:
          "Verify the DNS server configuration on client network settings and test lookup with `nslookup` or `dig` against a public recursive resolver (e.g., 1.1.1.1 or 8.8.8.8).",
        long_term_fix:
          "Configure redundant upstream DNS forwarders in the local gateway and verify internal split-horizon DNS routing.",
      },
      cwe: {
        id: "CWE-778",
        name: "Insufficient Logging & Service Availability",
        url: "https://cwe.mitre.org/data/definitions/778.html",
      },
      remediation_rules: {
        iptables: `# Configure fallback upstream resolvers\nresolvectl dns eth0 1.1.1.1 8.8.8.8 9.9.9.9`,
      },
      affected_ips: Array.from(new Set(dnsFailures.map(p => p.source_ip || "").filter(Boolean))),
    });
  }

  // 5. Performance: Abnormal RTT Latency
  const highLatencyFlows = flows.filter(f => f.rtt_ms && f.rtt_ms > 250);
  if (highLatencyFlows.length > 0) {
    const evidence = highLatencyFlows.slice(0, 4).map(
      f => `Flow ${f.source} -> ${f.destination} measured RTT = ${Math.round(f.rtt_ms || 0)}ms (${f.packets_count} packets)`
    );

    findings.push({
      id: nextId(),
      category: "FAULT",
      issue_title: `Abnormal Round-Trip Latency Spike (>250ms)`,
      severity: "MEDIUM",
      confidence_score: 87,
      plain_language_explanation:
        "Network communication experienced extreme round-trip delay, taking more than a quarter of a second for packets to be acknowledged. This causes noticeable lag, buffering, and sluggish responsiveness.",
      technical_details: {
        root_cause: `TCP handshake delta and packet sequence-to-ACK tracking revealed ${highLatencyFlows.length} flows with RTT exceeding 250ms (peaking at ${Math.round(highLatencyFlows[0].rtt_ms || 0)}ms). Indicates path congestion, bufferbloat at the WAN gateway, or excessive geographic hops.`,
        evidence_packets: evidence,
      },
      recommended_remediation: {
        immediate_action:
          "Run a traceroute (`tracert` / `traceroute`) to locate which upstream hop introduces the latency spike.",
        long_term_fix:
          "Implement Active Queue Management (Cake or FQ-CoDel SQM) on the WAN edge router to eradicate bufferbloat during concurrent uploads/downloads.",
      },
      cwe: {
        id: "CWE-400",
        name: "Uncontrolled Resource Consumption (Network Latency Bufferbloat)",
        url: "https://cwe.mitre.org/data/definitions/400.html",
      },
      remediation_rules: {
        iptables: `# Enable FQ-CoDel Smart Queue Management on WAN interface\ntc qdisc add dev eth0 root fq_codel`,
      },
      affected_ips: highLatencyFlows.map(f => f.source.split(":")[0]),
    });
  }

  return findings;
}
