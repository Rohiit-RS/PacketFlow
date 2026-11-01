/**
 * Realistic packet capture scenarios for Hackathon evaluation and immediate 1-click test runs.
 * Covers ARP MITM, SYN scans, DNS exfiltration, TCP congestion, rogue DHCP, MTU mismatch, and healthy traffic.
 */

import { ParsedPacket } from "../engine/types";

export interface SampleCaptureScenario {
  id: string;
  name: string;
  category: "ATTACK" | "FAULT" | "MIXED" | "HEALTHY";
  badge: string;
  description: string;
  packetCount: number;
  packets: ParsedPacket[];
}

/** 1. ARP Spoofing / Man-in-the-Middle Attack */
const arpSpoofPackets: ParsedPacket[] = [
  {
    frame_number: 1,
    timestamp: 1730419200.0,
    timestamp_iso: "2026-10-31T21:00:00.000Z",
    length: 60,
    protocol: "ARP",
    source_mac: "00:1a:2b:3c:4d:01",
    destination_mac: "ff:ff:ff:ff:ff:ff",
    arp_opcode: "REQUEST",
    arp_sender_mac: "00:1a:2b:3c:4d:01",
    arp_sender_ip: "192.168.1.50",
    arp_target_mac: "00:00:00:00:00:00",
    arp_target_ip: "192.168.1.1",
    info: "Who has 192.168.1.1? Tell 192.168.1.50",
  },
  {
    frame_number: 2,
    timestamp: 1730419200.002,
    timestamp_iso: "2026-10-31T21:00:00.002Z",
    length: 60,
    protocol: "ARP",
    source_mac: "00:50:56:c0:00:01",
    destination_mac: "00:1a:2b:3c:4d:01",
    arp_opcode: "REPLY",
    arp_sender_mac: "00:50:56:c0:00:01",
    arp_sender_ip: "192.168.1.1",
    arp_target_mac: "00:1a:2b:3c:4d:01",
    arp_target_ip: "192.168.1.50",
    info: "192.168.1.1 is at 00:50:56:c0:00:01 (Legitimate Gateway)",
  },
  // Attacker begins sending unsolicited ARP poison replies claiming router IP
  ...[3, 4, 5, 6, 7].map((num, i) => ({
    frame_number: num,
    timestamp: 1730419200.05 + i * 0.02,
    timestamp_iso: `2026-10-31T21:00:00.0${50 + i * 20}Z`,
    length: 60,
    protocol: "ARP" as const,
    source_mac: "00:0c:29:8a:4f:1b",
    destination_mac: "00:1a:2b:3c:4d:01",
    arp_opcode: "REPLY" as const,
    arp_sender_mac: "00:0c:29:8a:4f:1b",
    arp_sender_ip: "192.168.1.1",
    arp_target_mac: "00:1a:2b:3c:4d:01",
    arp_target_ip: "192.168.1.50",
    info: "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]",
  })),
  {
    frame_number: 8,
    timestamp: 1730419200.2,
    timestamp_iso: "2026-10-31T21:00:00.200Z",
    length: 120,
    protocol: "TCP",
    source_ip: "192.168.1.50",
    destination_ip: "93.184.216.34",
    source_mac: "00:1a:2b:3c:4d:01",
    destination_mac: "00:0c:29:8a:4f:1b", // Traffic redirected through attacker MAC!
    source_port: 52144,
    destination_port: 80,
    info: "52144 -> 80 [PSH, ACK] Intercepted HTTP Request routed via rogue MAC",
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 1,
    tcp_ack: 1,
    tcp_window_size: 64240,
    payload_preview: "GET /login HTTP/1.1\r\nHost: intranet.corp\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
  },
  // Retransmissions induced by hijacked route packet dropping
  ...[9, 10, 11, 12].map((num, i) => ({
    frame_number: num,
    timestamp: 1730419200.3 + i * 0.2,
    timestamp_iso: `2026-10-31T21:00:00.${300 + i * 200}Z`,
    length: 120,
    protocol: "TCP" as const,
    source_ip: "192.168.1.50",
    destination_ip: "93.184.216.34",
    source_mac: "00:1a:2b:3c:4d:01",
    destination_mac: "00:0c:29:8a:4f:1b",
    source_port: 52144,
    destination_port: 80,
    info: `52144 -> 80 [TCP Retransmission] Seq=1 Len=66 (Packet dropped by attacker)`,
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 1,
    tcp_ack: 1,
    tcp_window_size: 64240,
    payload_preview: "GET /login HTTP/1.1\r\nHost: intranet.corp\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n",
  })),
];

/** 2. Stealth SYN Port Scan & Subnet Reconnaissance */
const synScanPackets: ParsedPacket[] = [];
const scannedPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080];
let frameNum = 1;

for (const port of scannedPorts) {
  // Attacker sends SYN
  synScanPackets.push({
    frame_number: frameNum++,
    timestamp: 1730419210.0 + frameNum * 0.015,
    timestamp_iso: new Date((1730419210.0 + frameNum * 0.015) * 1000).toISOString(),
    length: 64,
    protocol: "TCP",
    source_ip: "10.0.0.88",
    destination_ip: "10.0.0.12",
    source_port: 45000 + frameNum,
    destination_port: port,
    tcp_flags: { syn: true },
    tcp_seq: 1000 + frameNum,
    tcp_window_size: 1024,
    info: `${45000 + frameNum} -> ${port} [SYN] Seq=${1000 + frameNum} Win=1024`,
  });

  // Victim responds with RST for closed ports or SYN-ACK for open 80, 443
  if (port === 80 || port === 443) {
    synScanPackets.push({
      frame_number: frameNum++,
      timestamp: 1730419210.0 + frameNum * 0.015,
      timestamp_iso: new Date((1730419210.0 + frameNum * 0.015) * 1000).toISOString(),
      length: 64,
      protocol: "TCP",
      source_ip: "10.0.0.12",
      destination_ip: "10.0.0.88",
      source_port: port,
      destination_port: 45000 + frameNum - 1,
      tcp_flags: { syn: true, ack: true },
      tcp_seq: 5000 + frameNum,
      tcp_ack: 1000 + frameNum,
      tcp_window_size: 65535,
      info: `${port} -> ${45000 + frameNum - 1} [SYN, ACK] Open Port Detected`,
    });
  } else {
    synScanPackets.push({
      frame_number: frameNum++,
      timestamp: 1730419210.0 + frameNum * 0.015,
      timestamp_iso: new Date((1730419210.0 + frameNum * 0.015) * 1000).toISOString(),
      length: 54,
      protocol: "TCP",
      source_ip: "10.0.0.12",
      destination_ip: "10.0.0.88",
      source_port: port,
      destination_port: 45000 + frameNum - 1,
      tcp_flags: { rst: true, ack: true },
      tcp_seq: 0,
      tcp_ack: 1000 + frameNum,
      tcp_window_size: 0,
      info: `${port} -> ${45000 + frameNum - 1} [RST, ACK] Closed Port`,
    });
  }
}

/** 3. DNS Tunneling & Rogue DNS Hijack */
const dnsTunnelPackets: ParsedPacket[] = [
  {
    frame_number: 1,
    timestamp: 1730419220.1,
    length: 135,
    protocol: "DNS",
    source_ip: "192.168.1.100",
    destination_ip: "192.168.1.1",
    source_port: 54123,
    destination_port: 53,
    dns_query: "aW5maWx0cmF0aW9uX2tleV9hYmMxMjM.tunnel.c2-command.org",
    dns_qtype: "TXT",
    info: "Standard query 0x1a2b TXT aW5maWx0cmF0aW9uX2tleV9hYmMxMjM.tunnel.c2-command.org",
  },
  {
    frame_number: 2,
    timestamp: 1730419220.15,
    length: 145,
    protocol: "DNS",
    source_ip: "192.168.1.100",
    destination_ip: "192.168.1.1",
    source_port: 54124,
    destination_port: 53,
    dns_query: "ZGF0YV9zdG9sZW5fcGFzc3dvcmRzX2V4ZmM.tunnel.c2-command.org",
    dns_qtype: "TXT",
    info: "Standard query 0x1a2c TXT ZGF0YV9zdG9sZW5fcGFzc3dvcmRzX2V4ZmM.tunnel.c2-command.org",
  },
  {
    frame_number: 3,
    timestamp: 1730419220.2,
    length: 150,
    protocol: "DNS",
    source_ip: "192.168.1.100",
    destination_ip: "192.168.1.1",
    source_port: 54125,
    destination_port: 53,
    dns_query: "ZXhpbF9jb21wYW55X3ByaXZhdGVfa2V5czE.tunnel.c2-command.org",
    dns_qtype: "TXT",
    info: "Standard query 0x1a2d TXT ZXhpbF9jb21wYW55X3ByaXZhdGVfa2V5czE.tunnel.c2-command.org",
  },
  // Rogue DNS server responds instead of legitimate gateway
  {
    frame_number: 4,
    timestamp: 1730419220.22,
    length: 110,
    protocol: "DNS",
    source_ip: "192.168.1.189", // Rogue workstation answering
    destination_ip: "192.168.1.100",
    source_port: 53,
    destination_port: 54123,
    dns_query: "bank-portal.internal",
    dns_response_code: 0,
    info: "Standard query response 0x1a2b NoError A bank-portal.internal -> 192.168.1.189 (Rogue Redirect)",
  },
  // Algorithmic DGA C2 queries
  {
    frame_number: 5,
    timestamp: 1730419220.35,
    length: 85,
    protocol: "DNS",
    source_ip: "192.168.1.100",
    destination_ip: "1.1.1.1",
    source_port: 54130,
    destination_port: 53,
    dns_query: "x8nz92mqkdfp.cc",
    dns_qtype: "A",
    info: "Standard query 0x2b3c A x8nz92mqkdfp.cc (DGA C2 Beacon)",
  },
  {
    frame_number: 6,
    timestamp: 1730419220.45,
    length: 85,
    protocol: "DNS",
    source_ip: "192.168.1.100",
    destination_ip: "1.1.1.1",
    source_port: 54131,
    destination_port: 53,
    dns_query: "q9vbt47xwzlp.biz",
    dns_qtype: "A",
    info: "Standard query 0x2b3d A q9vbt47xwzlp.biz (DGA C2 Beacon)",
  },
];

/** 4. Severe TCP Retransmission & Zero Window Outage */
const tcpOutagePackets: ParsedPacket[] = [];
let fNum = 1;
// Initial normal packets
for (let i = 0; i < 4; i++) {
  tcpOutagePackets.push({
    frame_number: fNum++,
    timestamp: 1730419230.0 + i * 0.05,
    length: 1460,
    protocol: "TCP",
    source_ip: "192.168.1.50",
    destination_ip: "10.0.0.200",
    source_port: 49152,
    destination_port: 443,
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 10000 + i * 1400,
    tcp_ack: 1,
    tcp_window_size: 65535,
    info: `49152 -> 443 [PSH, ACK] Seq=${10000 + i * 1400} Len=1400`,
  });
}
// Retransmissions
for (let i = 0; i < 5; i++) {
  tcpOutagePackets.push({
    frame_number: fNum++,
    timestamp: 1730419230.3 + i * 0.2,
    length: 1460,
    protocol: "TCP",
    source_ip: "192.168.1.50",
    destination_ip: "10.0.0.200",
    source_port: 49152,
    destination_port: 443,
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 11400, // exact same sequence resent
    tcp_ack: 1,
    tcp_window_size: 65535,
    info: `49152 -> 443 [TCP Retransmission] Seq=11400 Len=1400`,
  });
}
// Zero Window packets from receiver
for (let i = 0; i < 3; i++) {
  tcpOutagePackets.push({
    frame_number: fNum++,
    timestamp: 1730419231.5 + i * 0.1,
    length: 54,
    protocol: "TCP",
    source_ip: "10.0.0.200",
    destination_ip: "192.168.1.50",
    source_port: 443,
    destination_port: 49152,
    tcp_flags: { ack: true },
    tcp_seq: 1,
    tcp_ack: 11400,
    tcp_window_size: 0,
    info: `443 -> 49152 [TCP ZeroWindow] Win=0 Ack=11400`,
  });
}

/** 5. Rogue DHCP & Duplicate IP Conflict */
const rogueDhcpPackets: ParsedPacket[] = [
  {
    frame_number: 1,
    timestamp: 1730419240.0,
    length: 300,
    protocol: "DHCP",
    source_ip: "0.0.0.0",
    destination_ip: "255.255.255.255",
    source_port: 68,
    destination_port: 67,
    dhcp_msg_type: "DISCOVER",
    info: "DHCP DISCOVER - Client: bc:d0:74:11:22:33",
  },
  {
    frame_number: 2,
    timestamp: 1730419240.01,
    length: 320,
    protocol: "DHCP",
    source_ip: "192.168.1.1",
    destination_ip: "192.168.1.150",
    source_port: 67,
    destination_port: 68,
    dhcp_msg_type: "OFFER",
    dhcp_server_id: "192.168.1.1",
    info: "DHCP OFFER - Offered: 192.168.1.150 from Authorized Gateway 192.168.1.1",
  },
  {
    frame_number: 3,
    timestamp: 1730419240.012,
    length: 320,
    protocol: "DHCP",
    source_ip: "192.168.1.200", // Rogue server
    destination_ip: "192.168.1.150",
    source_port: 67,
    destination_port: 68,
    dhcp_msg_type: "OFFER",
    dhcp_server_id: "192.168.1.200",
    info: "DHCP OFFER - Offered: 192.168.1.150 from Rogue Server 192.168.1.200",
  },
  // Duplicate IP ARP collision
  {
    frame_number: 4,
    timestamp: 1730419240.5,
    length: 60,
    protocol: "ARP",
    arp_opcode: "REPLY",
    arp_sender_ip: "192.168.1.45",
    arp_sender_mac: "14:cc:20:99:aa:01",
    info: "192.168.1.45 is at 14:cc:20:99:aa:01 (Host A)",
  },
  {
    frame_number: 5,
    timestamp: 1730419240.55,
    length: 60,
    protocol: "ARP",
    arp_opcode: "REPLY",
    arp_sender_ip: "192.168.1.45",
    arp_sender_mac: "52:54:00:12:34:56",
    info: "192.168.1.45 is at 52:54:00:12:34:56 (Host B - Cloned VM collision)",
  },
];

/** 6. MTU Mismatch & Path MTU Black Hole */
const mtuMismatchPackets: ParsedPacket[] = [
  {
    frame_number: 1,
    timestamp: 1730419250.0,
    length: 1514,
    protocol: "TCP",
    source_ip: "192.168.1.80",
    destination_ip: "198.51.100.22",
    source_port: 44300,
    destination_port: 443,
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 50000,
    info: "44300 -> 443 [PSH, ACK] Large payload length=1500 (DF bit set)",
  },
  {
    frame_number: 2,
    timestamp: 1730419250.035,
    length: 70,
    protocol: "ICMP",
    source_ip: "192.168.1.1",
    destination_ip: "192.168.1.80",
    icmp_type: 3,
    icmp_code: 4,
    info: "ICMP Destination unreachable (Fragmentation needed and DF set, Next MTU: 1420)",
  },
  {
    frame_number: 3,
    timestamp: 1730419250.2,
    length: 1514,
    protocol: "TCP",
    source_ip: "192.168.1.80",
    destination_ip: "198.51.100.22",
    source_port: 44300,
    destination_port: 443,
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 50000,
    info: "44300 -> 443 [TCP Retransmission] Large payload length=1500",
  },
  {
    frame_number: 4,
    timestamp: 1730419250.24,
    length: 70,
    protocol: "ICMP",
    source_ip: "192.168.1.1",
    destination_ip: "192.168.1.80",
    icmp_type: 3,
    icmp_code: 4,
    info: "ICMP Destination unreachable (Fragmentation needed and DF set, Next MTU: 1420)",
  },
];

/** 7. Clean Healthy Traffic Baseline */
const healthyPackets: ParsedPacket[] = [
  {
    frame_number: 1,
    timestamp: 1730419260.0,
    length: 78,
    protocol: "DNS",
    source_ip: "192.168.1.50",
    destination_ip: "1.1.1.1",
    source_port: 52110,
    destination_port: 53,
    dns_query: "api.github.com",
    dns_qtype: "A",
    info: "Standard query 0x7a8b A api.github.com",
  },
  {
    frame_number: 2,
    timestamp: 1730419260.015,
    length: 94,
    protocol: "DNS",
    source_ip: "1.1.1.1",
    destination_ip: "192.168.1.50",
    source_port: 53,
    destination_port: 52110,
    dns_query: "api.github.com",
    dns_response_code: 0,
    info: "Standard query response 0x7a8b NoError A api.github.com -> 140.82.121.6",
  },
  {
    frame_number: 3,
    timestamp: 1730419260.02,
    length: 66,
    protocol: "TCP",
    source_ip: "192.168.1.50",
    destination_ip: "140.82.121.6",
    source_port: 53120,
    destination_port: 443,
    tcp_flags: { syn: true },
    tcp_seq: 100,
    tcp_window_size: 65535,
    info: "53120 -> 443 [SYN] Seq=100 Win=65535",
  },
  {
    frame_number: 4,
    timestamp: 1730419260.038,
    length: 66,
    protocol: "TCP",
    source_ip: "140.82.121.6",
    destination_ip: "192.168.1.50",
    source_port: 443,
    destination_port: 53120,
    tcp_flags: { syn: true, ack: true },
    tcp_seq: 200,
    tcp_ack: 101,
    tcp_window_size: 65535,
    info: "443 -> 53120 [SYN, ACK] Seq=200 Ack=101 Win=65535",
  },
  {
    frame_number: 5,
    timestamp: 1730419260.039,
    length: 54,
    protocol: "TCP",
    source_ip: "192.168.1.50",
    destination_ip: "140.82.121.6",
    source_port: 53120,
    destination_port: 443,
    tcp_flags: { ack: true },
    tcp_seq: 101,
    tcp_ack: 201,
    tcp_window_size: 65535,
    info: "53120 -> 443 [ACK] Seq=101 Ack=201 Win=65535",
  },
  {
    frame_number: 6,
    timestamp: 1730419260.045,
    length: 512,
    protocol: "TCP",
    source_ip: "192.168.1.50",
    destination_ip: "140.82.121.6",
    source_port: 53120,
    destination_port: 443,
    tcp_flags: { psh: true, ack: true },
    tcp_seq: 101,
    tcp_ack: 201,
    tcp_window_size: 65535,
    info: "53120 -> 443 [PSH, ACK] TLS 1.3 Client Hello",
  },
];

export const SAMPLE_SCENARIOS: SampleCaptureScenario[] = [
  {
    id: "arp_mitm",
    name: "ARP Spoofing & Gateway Hijacking",
    category: "ATTACK",
    badge: "Malicious Attack",
    description: "Attacker broadcasting unsolicited ARP replies to impersonate router and intercept credentials.",
    packetCount: arpSpoofPackets.length,
    packets: arpSpoofPackets,
  },
  {
    id: "syn_scan",
    name: "Stealth SYN Port Scan & Recon",
    category: "ATTACK",
    badge: "Recon Attack",
    description: "Nmap-style half-open SYN scan probing 15 consecutive service ports on target host.",
    packetCount: synScanPackets.length,
    packets: synScanPackets,
  },
  {
    id: "dns_tunnel",
    name: "DNS Exfiltration & Rogue Server",
    category: "ATTACK",
    badge: "Data Exfiltration",
    description: "Covert high-entropy DNS tunneling queries coupled with an unauthorized internal DNS responder.",
    packetCount: dnsTunnelPackets.length,
    packets: dnsTunnelPackets,
  },
  {
    id: "tcp_outage",
    name: "TCP Congestion & Zero Window Outage",
    category: "FAULT",
    badge: "Operational Fault",
    description: "Severe packet loss causing repeated TCP retransmissions and receiver buffer exhaustion.",
    packetCount: tcpOutagePackets.length,
    packets: tcpOutagePackets,
  },
  {
    id: "rogue_dhcp",
    name: "Rogue DHCP Server & IP Conflict",
    category: "MIXED",
    badge: "Mixed Incident",
    description: "Conflicting DHCP OFFER frames from an unauthorized gateway along with duplicate IP collision.",
    packetCount: rogueDhcpPackets.length,
    packets: rogueDhcpPackets,
  },
  {
    id: "mtu_blackhole",
    name: "MTU Mismatch & Fragmentation Fault",
    category: "FAULT",
    badge: "Routing Fault",
    description: "ICMP Type 3 Code 4 fragmentation needed packets dropped by VPN tunnel MTU constriction.",
    packetCount: mtuMismatchPackets.length,
    packets: mtuMismatchPackets,
  },
  {
    id: "healthy_baseline",
    name: "Clean High-Performance Baseline",
    category: "HEALTHY",
    badge: "Healthy Traffic",
    description: "Normal internet traffic with valid DNS resolution, completed 3-way TLS handshakes, and 0 errors.",
    packetCount: healthyPackets.length,
    packets: healthyPackets,
  },
];
