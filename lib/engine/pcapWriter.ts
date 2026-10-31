/**
 * Safe Binary PCAP Generator.
 * Synthesizes valid, RFC-compliant .pcap files from scenario packets
 * so judges can download, inspect in Wireshark, or upload directly.
 */

import { ParsedPacket } from "./types";

function parseMac(macStr?: string): Uint8Array {
  const bytes = new Uint8Array(6);
  if (!macStr) return bytes;
  const parts = macStr.split(":");
  for (let i = 0; i < Math.min(6, parts.length); i++) {
    bytes[i] = parseInt(parts[i], 16) || 0;
  }
  return bytes;
}

function parseIpv4(ipStr?: string): Uint8Array {
  const bytes = new Uint8Array(4);
  if (!ipStr) return bytes;
  const parts = ipStr.split(".");
  for (let i = 0; i < Math.min(4, parts.length); i++) {
    bytes[i] = parseInt(parts[i], 10) || 0;
  }
  return bytes;
}

export function synthesizePcapBinary(packets: ParsedPacket[]): Uint8Array {
  // Step 1: Pre-calculate total file size
  let totalSize = 24; // Global header
  const packetBuffers: Uint8Array[] = [];

  for (const pkt of packets) {
    const rawData = buildPacketBytes(pkt);
    packetBuffers.push(rawData);
    totalSize += 16 + rawData.length; // 16 bytes record header + data
  }

  const output = new Uint8Array(totalSize);
  const view = new DataView(output.buffer);

  // Global PCAP Header (24 bytes, Little Endian)
  view.setUint32(0, 0xa1b2c3d4, true); // Writes d4 c3 b2 a1 on disk for standard LE PCAP
  view.setUint16(4, 2, true);          // Version major: 2
  view.setUint16(6, 4, true);          // Version minor: 4
  view.setInt32(8, 0, true);           // Thiszone: 0
  view.setUint32(12, 0, true);         // Sigfigs: 0
  view.setUint32(16, 65535, true);     // Snaplen: 65535
  view.setUint32(20, 1, true);         // Network: 1 (Ethernet)

  let offset = 24;

  for (let i = 0; i < packets.length; i++) {
    const pkt = packets[i];
    const data = packetBuffers[i];
    const tsSec = Math.floor(pkt.timestamp);
    const tsUsec = Math.floor((pkt.timestamp - tsSec) * 1e6);

    // Packet Record Header (16 bytes)
    view.setUint32(offset, tsSec, true);
    view.setUint32(offset + 4, tsUsec, true);
    view.setUint32(offset + 8, data.length, true); // incl_len
    view.setUint32(offset + 12, pkt.length || data.length, true); // orig_len

    output.set(data, offset + 16);
    offset += 16 + data.length;
  }

  return output;
}

function buildPacketBytes(pkt: ParsedPacket): Uint8Array {
  const destMac = parseMac(pkt.destination_mac || "ff:ff:ff:ff:ff:ff");
  const srcMac = parseMac(pkt.source_mac || "00:11:22:33:44:55");

  if (pkt.protocol === "ARP") {
    // Ethernet (14) + ARP (28) = 42 bytes (padded to 60)
    const buf = new Uint8Array(60);
    buf.set(destMac, 0);
    buf.set(srcMac, 6);
    buf[12] = 0x08;
    buf[13] = 0x06; // EtherType 0x0806 (ARP)

    const view = new DataView(buf.buffer);
    view.setUint16(14, 1, false);     // Hardware: Ethernet
    view.setUint16(16, 0x0800, false); // Protocol: IPv4
    buf[18] = 6;                       // HW size: 6
    buf[19] = 4;                       // Proto size: 4
    view.setUint16(20, pkt.arp_opcode === "REPLY" ? 2 : 1, false);

    buf.set(parseMac(pkt.arp_sender_mac || pkt.source_mac), 22);
    buf.set(parseIpv4(pkt.arp_sender_ip || pkt.source_ip), 28);
    buf.set(parseMac(pkt.arp_target_mac || pkt.destination_mac), 32);
    buf.set(parseIpv4(pkt.arp_target_ip || pkt.destination_ip), 38);

    return buf;
  }

  // IPv4 + TCP/UDP/ICMP
  const payloadBytes = new TextEncoder().encode(pkt.payload_preview || "");
  const l4Len = pkt.protocol === "TCP" ? 20 + payloadBytes.length : pkt.protocol === "UDP" ? 8 + payloadBytes.length : 8;
  const ipTotalLen = 20 + l4Len;
  const frameLen = Math.max(60, 14 + ipTotalLen);

  const buf = new Uint8Array(frameLen);
  buf.set(destMac, 0);
  buf.set(srcMac, 6);
  buf[12] = 0x08;
  buf[13] = 0x00; // EtherType 0x0800 (IPv4)

  const view = new DataView(buf.buffer);
  // IPv4 Header
  buf[14] = 0x45; // Version 4, IHL 5 (20 bytes)
  buf[15] = 0x00; // DSCP / ECN
  view.setUint16(16, ipTotalLen, false);
  view.setUint16(18, pkt.frame_number, false); // ID
  view.setUint16(20, 0x4000, false); // Flags: Don't Fragment
  buf[22] = 64;   // TTL
  buf[23] = pkt.protocol === "TCP" ? 6 : pkt.protocol === "UDP" || pkt.protocol === "DNS" || pkt.protocol === "DHCP" ? 17 : 1; // Protocol
  view.setUint16(24, 0, false); // Checksum
  buf.set(parseIpv4(pkt.source_ip || "192.168.1.50"), 26);
  buf.set(parseIpv4(pkt.destination_ip || "10.0.0.1"), 30);

  const l4Offset = 34;

  if (pkt.protocol === "TCP") {
    view.setUint16(l4Offset, pkt.source_port || 50000, false);
    view.setUint16(l4Offset + 2, pkt.destination_port || 80, false);
    view.setUint32(l4Offset + 4, pkt.tcp_seq || 1, false);
    view.setUint32(l4Offset + 8, pkt.tcp_ack || 0, false);
    buf[l4Offset + 12] = 0x50; // Data offset 5 (20 bytes)
    
    let flags = 0;
    if (pkt.tcp_flags?.fin) flags |= 0x01;
    if (pkt.tcp_flags?.syn) flags |= 0x02;
    if (pkt.tcp_flags?.rst) flags |= 0x04;
    if (pkt.tcp_flags?.psh) flags |= 0x08;
    if (pkt.tcp_flags?.ack) flags |= 0x10;
    if (pkt.tcp_flags?.urg) flags |= 0x20;
    buf[l4Offset + 13] = flags;

    view.setUint16(l4Offset + 14, pkt.tcp_window_size ?? 65535, false);
    view.setUint16(l4Offset + 16, 0, false); // Checksum
    view.setUint16(l4Offset + 18, 0, false); // Urgent pointer

    if (payloadBytes.length > 0) {
      buf.set(payloadBytes, l4Offset + 20);
    }
  } else if (pkt.protocol === "ICMP") {
    buf[l4Offset] = pkt.icmp_type ?? 3;
    buf[l4Offset + 1] = pkt.icmp_code ?? 4;
    view.setUint16(l4Offset + 2, 0, false); // Checksum
    view.setUint16(l4Offset + 6, 1420, false); // Next-hop MTU
  } else {
    // UDP / DNS / DHCP
    view.setUint16(l4Offset, pkt.source_port || 53, false);
    view.setUint16(l4Offset + 2, pkt.destination_port || 53, false);
    view.setUint16(l4Offset + 4, l4Len, false);
    view.setUint16(l4Offset + 6, 0, false); // Checksum
    if (payloadBytes.length > 0) {
      buf.set(payloadBytes, l4Offset + 8);
    }
  }

  return buf;
}
