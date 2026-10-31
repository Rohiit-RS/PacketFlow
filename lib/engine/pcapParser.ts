/**
 * Pure TypeScript PCAP and PCAPNG binary parser.
 * Designed to safely read packet captures in both browser and serverless environments.
 * Handles corrupted headers, bounds-checks every byte slice, and prevents crashes.
 */

import { ParsedPacket } from "./types";
import { bytesToHexDump, bytesToSafeAscii, sanitizePayloadString } from "../utils/sanitizer";

export class SafeDataView {
  private view: DataView;
  private littleEndian: boolean;

  constructor(buffer: ArrayBuffer | Uint8Array, littleEndian = true) {
    if (buffer instanceof Uint8Array) {
      this.view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    } else {
      this.view = new DataView(buffer);
    }
    this.littleEndian = littleEndian;
  }

  get byteLength(): number {
    return this.view.byteLength;
  }

  setLittleEndian(le: boolean) {
    this.littleEndian = le;
  }

  getUint8(offset: number): number {
    if (offset < 0 || offset + 1 > this.view.byteLength) return 0;
    return this.view.getUint8(offset);
  }

  getUint16(offset: number, le = this.littleEndian): number {
    if (offset < 0 || offset + 2 > this.view.byteLength) return 0;
    return this.view.getUint16(offset, le);
  }

  getUint32(offset: number, le = this.littleEndian): number {
    if (offset < 0 || offset + 4 > this.view.byteLength) return 0;
    return this.view.getUint32(offset, le);
  }

  getBytes(offset: number, length: number): Uint8Array {
    if (offset < 0 || offset >= this.view.byteLength) return new Uint8Array(0);
    const safeLen = Math.min(length, this.view.byteLength - offset);
    return new Uint8Array(this.view.buffer, this.view.byteOffset + offset, safeLen);
  }
}

/** Formats MAC address bytes to string */
function formatMac(bytes: Uint8Array): string {
  if (bytes.length < 6) return "00:00:00:00:00:00";
  return Array.from(bytes.slice(0, 6))
    .map(b => b.toString(16).padStart(2, "0"))
    .join(":");
}

/** Formats IPv4 bytes to string */
function formatIpv4(bytes: Uint8Array, offset = 0): string {
  if (offset + 4 > bytes.length) return "0.0.0.0";
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

/** Formats IPv6 bytes to string */
function formatIpv6(bytes: Uint8Array, offset = 0): string {
  if (offset + 16 > bytes.length) return "::";
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
  }
  return parts.join(":");
}

/** Parses DNS domain name from packet buffer safely (supports compression pointers) */
function parseDnsDomain(reader: SafeDataView, offset: number, dnsStart: number, maxDepth = 10): { name: string; bytesRead: number } {
  let name = "";
  let cur = offset;
  let bytesRead = 0;
  let jumped = false;
  let depth = 0;

  while (cur < reader.byteLength && depth < maxDepth) {
    const len = reader.getUint8(cur);
    if (len === 0) {
      if (!jumped) bytesRead += 1;
      break;
    }

    // Check pointer (top two bits set: 11xxxxxx)
    if ((len & 0xc0) === 0xc0) {
      const ptrOffset = ((len & 0x3f) << 8) | reader.getUint8(cur + 1);
      if (!jumped) bytesRead += 2;
      jumped = true;
      cur = dnsStart + ptrOffset;
      depth++;
      continue;
    }

    // Normal label
    if (!jumped) bytesRead += 1 + len;
    cur += 1;
    let label = "";
    for (let i = 0; i < len && cur < reader.byteLength; i++) {
      label += String.fromCharCode(reader.getUint8(cur++));
    }
    if (name.length > 0) name += ".";
    name += label;
  }

  return { name: name || "<empty>", bytesRead: jumped ? bytesRead : cur - offset };
}

/**
 * Main binary parser for PCAP (.pcap) and PCAPNG (.pcapng) files.
 */
export function parsePcapBuffer(buffer: ArrayBuffer | Uint8Array, maxPackets = 10000): ParsedPacket[] {
  const reader = new SafeDataView(buffer);
  if (reader.byteLength < 24) {
    throw new Error("File too small to be a valid PCAP capture (minimum 24 bytes).");
  }

  const magic = reader.getUint32(0, false);

  // Check for PCAPNG (Section Header Block 0x0A0D0D0A)
  if (magic === 0x0a0d0d0a) {
    return parsePcapNg(reader, maxPackets);
  }

  // Check for classic PCAP magic numbers
  let littleEndian = true;
  let isNano = false;

  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
    isNano = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
    isNano = false;
  } else if (magic === 0xa1b23c4d) {
    littleEndian = false;
    isNano = true;
  } else if (magic === 0x4d3cb2a1) {
    littleEndian = true;
    isNano = true;
  } else {
    throw new Error(`Unrecognized packet capture header magic: 0x${magic.toString(16)}. Expected PCAP or PCAPNG.`);
  }

  reader.setLittleEndian(littleEndian);

  const linkType = reader.getUint32(20, littleEndian);
  // LinkType 1 = Ethernet (standard). If not 1, we still attempt best-effort parsing.

  const packets: ParsedPacket[] = [];
  let offset = 24; // PCAP global header is 24 bytes
  let frameNumber = 1;

  while (offset + 16 <= reader.byteLength && packets.length < maxPackets) {
    const tsSec = reader.getUint32(offset, littleEndian);
    const tsUsec = reader.getUint32(offset + 4, littleEndian);
    const inclLen = reader.getUint32(offset + 8, littleEndian);
    const origLen = reader.getUint32(offset + 12, littleEndian);

    offset += 16;

    if (inclLen <= 0 || inclLen > 65535 || offset + inclLen > reader.byteLength) {
      // Corrupt or truncated packet record, stop safely
      break;
    }

    const timestamp = tsSec + (isNano ? tsUsec / 1e9 : tsUsec / 1e6);
    const packetBytes = reader.getBytes(offset, inclLen);

    const parsed = parseEthernetFrame(packetBytes, frameNumber, timestamp, origLen);
    packets.push(parsed);

    offset += inclLen;
    frameNumber++;
  }

  return packets;
}

/** Parses PCAPNG files safely */
function parsePcapNg(reader: SafeDataView, maxPackets: number): ParsedPacket[] {
  let offset = 0;
  let littleEndian = true;
  const packets: ParsedPacket[] = [];
  let frameNumber = 1;

  while (offset + 8 <= reader.byteLength && packets.length < maxPackets) {
    const blockType = reader.getUint32(offset, littleEndian);
    const blockTotalLen = reader.getUint32(offset + 4, littleEndian);

    if (blockTotalLen < 12 || offset + blockTotalLen > reader.byteLength) {
      break;
    }

    // Section Header Block (SHB)
    if (blockType === 0x0a0d0d0a) {
      const byteOrderMagic = reader.getUint32(offset + 8, false);
      littleEndian = byteOrderMagic !== 0x1a2b3c4d;
    } 
    // Enhanced Packet Block (EPB)
    else if (blockType === 0x00000006) {
      const tsHigh = reader.getUint32(offset + 12, littleEndian);
      const tsLow = reader.getUint32(offset + 16, littleEndian);
      const capLen = reader.getUint32(offset + 20, littleEndian);
      const origLen = reader.getUint32(offset + 24, littleEndian);

      const ts64 = BigInt(tsHigh) * BigInt(2 ** 32) + BigInt(tsLow);
      const timestamp = Number(ts64) / 1e6; // Default microsecond resolution

      const packetOffset = offset + 28;
      if (capLen > 0 && packetOffset + capLen <= offset + blockTotalLen) {
        const packetBytes = reader.getBytes(packetOffset, capLen);
        const parsed = parseEthernetFrame(packetBytes, frameNumber, timestamp, origLen);
        packets.push(parsed);
        frameNumber++;
      }
    }
    // Simple Packet Block (SPB)
    else if (blockType === 0x00000003) {
      const origLen = reader.getUint32(offset + 8, littleEndian);
      const capLen = blockTotalLen - 16;
      if (capLen > 0) {
        const packetBytes = reader.getBytes(offset + 12, capLen);
        const parsed = parseEthernetFrame(packetBytes, frameNumber, Date.now() / 1000, origLen);
        packets.push(parsed);
        frameNumber++;
      }
    }

    offset += blockTotalLen;
  }

  return packets;
}

/** Parses single Ethernet frame into higher layer protocols */
export function parseEthernetFrame(
  bytes: Uint8Array,
  frameNumber: number,
  timestamp: number,
  origLen: number
): ParsedPacket {
  const packet: ParsedPacket = {
    frame_number: frameNumber,
    timestamp: timestamp,
    timestamp_iso: new Date(timestamp * 1000).toISOString(),
    length: origLen || bytes.length,
    protocol: "OTHER",
    info: `Frame ${frameNumber} (${bytes.length} bytes)`,
  };

  if (bytes.length < 14) {
    packet.info = `Malformed Short Ethernet Frame (${bytes.length} bytes)`;
    return packet;
  }

  const destMac = formatMac(bytes.slice(0, 6));
  const srcMac = formatMac(bytes.slice(6, 12));
  let etherType = (bytes[12] << 8) | bytes[13];
  let l3Offset = 14;

  // Handle 802.1Q VLAN Tagging
  if (etherType === 0x8100 && bytes.length >= 18) {
    etherType = (bytes[16] << 8) | bytes[17];
    l3Offset = 18;
  }

  packet.source_mac = srcMac;
  packet.destination_mac = destMac;
  packet.ether_type = `0x${etherType.toString(16).padStart(4, "0").toUpperCase()}`;

  // IPv4 Protocol (0x0800)
  if (etherType === 0x0800 && bytes.length >= l3Offset + 20) {
    parseIpv4(packet, bytes, l3Offset);
  }
  // ARP Protocol (0x0806)
  else if (etherType === 0x0806 && bytes.length >= l3Offset + 28) {
    parseArp(packet, bytes, l3Offset);
  }
  // IPv6 Protocol (0x86DD)
  else if (etherType === 0x86dd && bytes.length >= l3Offset + 40) {
    parseIpv6(packet, bytes, l3Offset);
  } else {
    packet.info = `Ethernet II, Src: ${srcMac}, Dst: ${destMac}, Type: ${packet.ether_type}`;
  }

  // Safe preview of raw payload
  if (bytes.length > 0) {
    packet.payload_preview = sanitizePayloadString(bytesToSafeAscii(bytes.slice(-Math.min(64, bytes.length))));
    packet.payload_hex = bytesToHexDump(bytes, 128).join("\n");
    packet.payload_size = bytes.length;
  }

  return packet;
}

/** Parses IPv4 layer */
function parseIpv4(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  const versionIhl = bytes[offset];
  const version = versionIhl >> 4;
  const ihl = (versionIhl & 0x0f) * 4;

  if (version !== 4 || ihl < 20 || offset + ihl > bytes.length) {
    packet.info = "Corrupted IPv4 Header";
    return;
  }

  const protocolNum = bytes[offset + 9];
  const srcIp = formatIpv4(bytes, offset + 12);
  const dstIp = formatIpv4(bytes, offset + 16);

  packet.ip_version = 4;
  packet.source_ip = srcIp;
  packet.destination_ip = dstIp;

  const l4Offset = offset + ihl;

  // TCP (Protocol 6)
  if (protocolNum === 6 && bytes.length >= l4Offset + 20) {
    parseTcp(packet, bytes, l4Offset);
  }
  // UDP (Protocol 17)
  else if (protocolNum === 17 && bytes.length >= l4Offset + 8) {
    parseUdp(packet, bytes, l4Offset);
  }
  // ICMP (Protocol 1)
  else if (protocolNum === 1 && bytes.length >= l4Offset + 8) {
    parseIcmp(packet, bytes, l4Offset);
  } else {
    packet.protocol = "OTHER";
    packet.info = `IPv4 ${srcIp} -> ${dstIp} (Protocol ${protocolNum})`;
  }
}

/** Parses IPv6 layer */
function parseIpv6(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  const nextHeader = bytes[offset + 6];
  const srcIp = formatIpv6(bytes, offset + 8);
  const dstIp = formatIpv6(bytes, offset + 24);

  packet.ip_version = 6;
  packet.source_ip = srcIp;
  packet.destination_ip = dstIp;

  const l4Offset = offset + 40;
  if (nextHeader === 6 && bytes.length >= l4Offset + 20) {
    parseTcp(packet, bytes, l4Offset);
  } else if (nextHeader === 17 && bytes.length >= l4Offset + 8) {
    parseUdp(packet, bytes, l4Offset);
  } else {
    packet.protocol = "OTHER";
    packet.info = `IPv6 ${srcIp} -> ${dstIp} (Next Header ${nextHeader})`;
  }
}

/** Parses ARP layer */
function parseArp(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  packet.protocol = "ARP";
  const opcodeNum = (bytes[offset + 6] << 8) | bytes[offset + 7];
  const senderMac = formatMac(bytes.slice(offset + 8, offset + 14));
  const senderIp = formatIpv4(bytes, offset + 14);
  const targetMac = formatMac(bytes.slice(offset + 18, offset + 24));
  const targetIp = formatIpv4(bytes, offset + 24);

  packet.arp_opcode = opcodeNum === 1 ? "REQUEST" : opcodeNum === 2 ? "REPLY" : undefined;
  packet.arp_sender_mac = senderMac;
  packet.arp_sender_ip = senderIp;
  packet.arp_target_mac = targetMac;
  packet.arp_target_ip = targetIp;

  if (opcodeNum === 1) {
    if (senderIp === targetIp) {
      packet.info = `Gratuitous ARP Announcement for ${senderIp} (${senderMac})`;
    } else {
      packet.info = `Who has ${targetIp}? Tell ${senderIp}`;
    }
  } else if (opcodeNum === 2) {
    packet.info = `${senderIp} is at ${senderMac}`;
  } else {
    packet.info = `ARP Opcode ${opcodeNum}`;
  }
}

/** Parses TCP layer */
function parseTcp(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  packet.protocol = "TCP";
  const srcPort = (bytes[offset] << 8) | bytes[offset + 1];
  const dstPort = (bytes[offset + 2] << 8) | bytes[offset + 3];
  const seqNum = ((bytes[offset + 4] << 24) | (bytes[offset + 5] << 16) | (bytes[offset + 6] << 8) | bytes[offset + 7]) >>> 0;
  const ackNum = ((bytes[offset + 8] << 24) | (bytes[offset + 9] << 16) | (bytes[offset + 10] << 8) | bytes[offset + 11]) >>> 0;
  
  const dataOffset = (bytes[offset + 12] >> 4) * 4;
  const flagsByte = bytes[offset + 13];
  const winSize = (bytes[offset + 14] << 8) | bytes[offset + 15];

  const syn = Boolean(flagsByte & 0x02);
  const ack = Boolean(flagsByte & 0x10);
  const rst = Boolean(flagsByte & 0x04);
  const fin = Boolean(flagsByte & 0x01);
  const psh = Boolean(flagsByte & 0x08);
  const urg = Boolean(flagsByte & 0x20);

  packet.source_port = srcPort;
  packet.destination_port = dstPort;
  packet.tcp_seq = seqNum;
  packet.tcp_ack = ackNum;
  packet.tcp_window_size = winSize;
  packet.tcp_flags = { syn, ack, rst, fin, psh, urg };

  const flagNames: string[] = [];
  if (syn) flagNames.push("SYN");
  if (ack) flagNames.push("ACK");
  if (rst) flagNames.push("RST");
  if (fin) flagNames.push("FIN");
  if (psh) flagNames.push("PSH");
  if (urg) flagNames.push("URG");

  const flagsStr = flagNames.length > 0 ? `[${flagNames.join(", ")}]` : "[NONE]";
  packet.info = `${srcPort} -> ${dstPort} ${flagsStr} Seq=${seqNum} Ack=${ackNum} Win=${winSize}`;

  // Check HTTP or TLS payload
  const payloadOffset = offset + dataOffset;
  if (payloadOffset < bytes.length) {
    const payloadBytes = bytes.slice(payloadOffset);
    const ascii = bytesToSafeAscii(payloadBytes.slice(0, 80));
    if (ascii.startsWith("GET ") || ascii.startsWith("POST ") || ascii.startsWith("HTTP/1.")) {
      packet.info += ` | HTTP: ${ascii.split("\r\n")[0]}`;
    }
  }
}

/** Parses UDP layer */
function parseUdp(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  const srcPort = (bytes[offset] << 8) | bytes[offset + 1];
  const dstPort = (bytes[offset + 2] << 8) | bytes[offset + 3];
  const length = (bytes[offset + 4] << 8) | bytes[offset + 5];

  packet.source_port = srcPort;
  packet.destination_port = dstPort;
  packet.protocol = "UDP";

  const payloadOffset = offset + 8;
  const payloadLen = Math.min(length - 8, bytes.length - payloadOffset);

  // Check DNS (Port 53)
  if ((srcPort === 53 || dstPort === 53) && payloadLen >= 12) {
    parseDns(packet, bytes, payloadOffset);
    return;
  }

  // Check DHCP (Ports 67 / 68)
  if ((srcPort === 67 || dstPort === 67 || srcPort === 68 || dstPort === 68) && payloadLen >= 240) {
    parseDhcp(packet, bytes, payloadOffset);
    return;
  }

  packet.info = `${srcPort} -> ${dstPort} Len=${length}`;
}

/** Parses DNS queries & responses */
function parseDns(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  packet.protocol = "DNS";
  const reader = new SafeDataView(bytes);
  const dnsStart = offset;

  const id = reader.getUint16(offset);
  const flags = reader.getUint16(offset + 2);
  const qdCount = reader.getUint16(offset + 4);
  const anCount = reader.getUint16(offset + 6);

  const qr = (flags & 0x8000) !== 0; // 0 = query, 1 = response
  const rcode = flags & 0x000f;

  packet.dns_response_code = rcode;

  if (qdCount > 0 && offset + 12 < bytes.length) {
    const { name, bytesRead } = parseDnsDomain(reader, offset + 12, dnsStart);
    packet.dns_query = name;

    const qtypeOffset = offset + 12 + bytesRead;
    const qtype = reader.getUint16(qtypeOffset);
    packet.dns_qtype = qtype === 1 ? "A" : qtype === 28 ? "AAAA" : qtype === 16 ? "TXT" : qtype === 5 ? "CNAME" : `TYPE${qtype}`;

    if (!qr) {
      packet.info = `Standard query 0x${id.toString(16)} ${packet.dns_qtype} ${name}`;
    } else {
      const rcodeNames: Record<number, string> = {
        0: "NoError",
        1: "FormatError",
        2: "ServerFailure",
        3: "NXDomain",
        5: "Refused",
      };
      const rcodeStr = rcodeNames[rcode] || `RCODE${rcode}`;
      packet.info = `Standard query response 0x${id.toString(16)} ${rcodeStr} ${packet.dns_qtype} ${name}`;
    }
  } else {
    packet.info = `DNS ${qr ? "Response" : "Query"} ID 0x${id.toString(16)}`;
  }
}

/** Parses DHCP (BOOTP) */
function parseDhcp(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  packet.protocol = "DHCP";
  const reader = new SafeDataView(bytes);

  const op = reader.getUint8(offset); // 1 = BOOTREQUEST, 2 = BOOTREPLY
  const yiaddr = formatIpv4(bytes, offset + 16);
  const chaddr = formatMac(bytes.slice(offset + 28, offset + 34));

  // Magic cookie check 0x63825363
  const magic = reader.getUint32(offset + 236, false);
  if (magic === 0x63825363) {
    let optOffset = offset + 240;
    while (optOffset < bytes.length) {
      const optCode = reader.getUint8(optOffset);
      if (optCode === 255) break; // End option
      if (optCode === 0) {
        optOffset += 1;
        continue;
      }
      const optLen = reader.getUint8(optOffset + 1);
      if (optCode === 53 && optLen === 1) { // DHCP Message Type
        const msgTypeNum = reader.getUint8(optOffset + 2);
        const types: Record<number, "DISCOVER" | "OFFER" | "REQUEST" | "ACK" | "NAK" | "DECLINE" | "RELEASE"> = {
          1: "DISCOVER",
          2: "OFFER",
          3: "REQUEST",
          4: "DECLINE",
          5: "ACK",
          6: "NAK",
          7: "RELEASE",
        };
        packet.dhcp_msg_type = types[msgTypeNum];
      } else if (optCode === 54 && optLen === 4) { // Server Identifier
        packet.dhcp_server_id = formatIpv4(bytes, optOffset + 2);
      }
      optOffset += 2 + optLen;
    }
  }

  const typeStr = packet.dhcp_msg_type ? `DHCP ${packet.dhcp_msg_type}` : `DHCP Op ${op}`;
  packet.info = `${typeStr} - Client: ${chaddr} ${yiaddr !== "0.0.0.0" ? `Offered: ${yiaddr}` : ""}`;
}

/** Parses ICMP */
function parseIcmp(packet: ParsedPacket, bytes: Uint8Array, offset: number) {
  packet.protocol = "ICMP";
  const type = bytes[offset];
  const code = bytes[offset + 1];

  packet.icmp_type = type;
  packet.icmp_code = code;

  let desc = `Type ${type}, Code ${code}`;
  if (type === 8) desc = "Echo (ping) request";
  else if (type === 0) desc = "Echo (ping) reply";
  else if (type === 3) {
    if (code === 4) desc = "Destination unreachable (Fragmentation needed and DF set)";
    else if (code === 3) desc = "Destination unreachable (Port unreachable)";
    else if (code === 1) desc = "Destination unreachable (Host unreachable)";
    else desc = `Destination unreachable (Code ${code})`;
  } else if (type === 11) desc = "Time-to-live exceeded";

  packet.icmp_description = desc;
  packet.info = `ICMP ${desc}`;
}

/**
 * Safely parses JSON telemetry data or packet logs (e.g. from Wireshark -T json or custom scripts)
 */
export function parseTelemetryJson(jsonString: string): ParsedPacket[] {
  try {
    const data = JSON.parse(jsonString);
    if (Array.isArray(data)) {
      return data.map((item, idx) => ({
        frame_number: item.frame_number || item.id || idx + 1,
        timestamp: item.timestamp || (Date.now() / 1000) + (idx * 0.05),
        timestamp_iso: item.timestamp_iso || new Date().toISOString(),
        length: item.length || item.size || 64,
        source_ip: item.source_ip || item.src || item.src_ip || "192.168.1.100",
        destination_ip: item.destination_ip || item.dst || item.dst_ip || "192.168.1.1",
        source_mac: item.source_mac || item.src_mac,
        destination_mac: item.destination_mac || item.dst_mac,
        protocol: (item.protocol || "TCP").toUpperCase(),
        source_port: item.source_port || item.src_port,
        destination_port: item.destination_port || item.dst_port,
        info: sanitizePayloadString(item.info || item.summary || `${item.protocol} packet`),
        tcp_flags: item.tcp_flags,
        tcp_seq: item.tcp_seq,
        tcp_ack: item.tcp_ack,
        tcp_window_size: item.tcp_window_size,
        dns_query: item.dns_query,
        dns_qtype: item.dns_qtype,
        dns_response_code: item.dns_response_code,
        arp_opcode: item.arp_opcode,
        arp_sender_mac: item.arp_sender_mac,
        arp_sender_ip: item.arp_sender_ip,
        arp_target_mac: item.arp_target_mac,
        arp_target_ip: item.arp_target_ip,
        dhcp_msg_type: item.dhcp_msg_type,
        dhcp_server_id: item.dhcp_server_id,
        icmp_type: item.icmp_type,
        icmp_code: item.icmp_code,
      }));
    }
  } catch (err) {
    throw new Error(`Invalid JSON format: ${err instanceof Error ? err.message : String(err)}`);
  }
  throw new Error("JSON packet telemetry must be an array of packet objects.");
}
