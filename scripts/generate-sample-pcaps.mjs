import fs from "fs";
import path from "path";

// PCAP file header generator
function createPcapBytes(records) {
  let totalLen = 24;
  for (const r of records) {
    totalLen += 16 + r.data.length;
  }
  const buf = Buffer.alloc(totalLen);
  // Global Header (Standard Little-Endian PCAP: 0xd4, 0xc3, 0xb2, 0xa1)
  buf.writeUInt32LE(0xa1b2c3d4, 0); // Writes d4 c3 b2 a1 on disk
  buf.writeUInt16LE(2, 4);          // Major
  buf.writeUInt16LE(4, 6);          // Minor
  buf.writeInt32LE(0, 8);           // Timezone
  buf.writeUInt32LE(0, 12);         // Sigfigs
  buf.writeUInt32LE(65535, 16);     // Snaplen
  buf.writeUInt32LE(1, 20);         // Linktype Ethernet

  let offset = 24;
  for (const r of records) {
    const sec = Math.floor(r.ts);
    const usec = Math.floor((r.ts - sec) * 1e6);
    buf.writeUInt32LE(sec, offset);
    buf.writeUInt32LE(usec, offset + 4);
    buf.writeUInt32LE(r.data.length, offset + 8);
    buf.writeUInt32LE(r.origLen || r.data.length, offset + 12);
    r.data.copy(buf, offset + 16);
    offset += 16 + r.data.length;
  }
  return buf;
}

function parseMac(s) {
  const parts = (s || "00:00:00:00:00:00").split(":");
  return Buffer.from(parts.map(p => parseInt(p, 16) || 0));
}

function parseIp(s) {
  const parts = (s || "0.0.0.0").split(".");
  return Buffer.from(parts.map(p => parseInt(p, 10) || 0));
}

function buildEthernetIpv4Tcp(srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, flags = 0x02, seq = 100, ack = 0, win = 65535, payload = "") {
  const payloadBuf = Buffer.from(payload);
  const totalIpLen = 40 + payloadBuf.length;
  const frameLen = Math.max(60, 14 + totalIpLen);
  const buf = Buffer.alloc(frameLen);

  parseMac(dstMac).copy(buf, 0);
  parseMac(srcMac).copy(buf, 6);
  buf.writeUInt16BE(0x0800, 12); // IPv4

  // IPv4 Header
  buf[14] = 0x45;
  buf.writeUInt16BE(totalIpLen, 16);
  buf.writeUInt16BE(1, 18);
  buf.writeUInt16BE(0x4000, 20); // DF
  buf[22] = 64; // TTL
  buf[23] = 6;  // TCP
  parseIp(srcIp).copy(buf, 26);
  parseIp(dstIp).copy(buf, 30);

  // TCP Header
  buf.writeUInt16BE(srcPort, 34);
  buf.writeUInt16BE(dstPort, 36);
  buf.writeUInt32BE(seq, 38);
  buf.writeUInt32BE(ack, 42);
  buf[46] = 0x50; // Offset 20 bytes
  buf[47] = flags;
  buf.writeUInt16BE(win, 48);

  if (payloadBuf.length > 0) {
    payloadBuf.copy(buf, 54);
  }

  return buf;
}

function buildEthernetArp(srcMac, dstMac, senderMac, senderIp, targetMac, targetIp, isReply = false) {
  const buf = Buffer.alloc(60);
  parseMac(dstMac).copy(buf, 0);
  parseMac(srcMac).copy(buf, 6);
  buf.writeUInt16BE(0x0806, 12); // ARP

  buf.writeUInt16BE(1, 14); // Ethernet
  buf.writeUInt16BE(0x0800, 16); // IPv4
  buf[18] = 6;
  buf[19] = 4;
  buf.writeUInt16BE(isReply ? 2 : 1, 20); // Opcode

  parseMac(senderMac).copy(buf, 22);
  parseIp(senderIp).copy(buf, 28);
  parseMac(targetMac).copy(buf, 32);
  parseIp(targetIp).copy(buf, 38);

  return buf;
}

const dir = path.join(process.cwd(), "sample-captures");
const pubDir = path.join(process.cwd(), "public", "sample-captures");
fs.mkdirSync(dir, { recursive: true });
fs.mkdirSync(pubDir, { recursive: true });

// 1. ARP Spoofing capture
const arpRecords = [
  { ts: 1730419200.0, data: buildEthernetArp("00:1a:2b:3c:4d:01", "ff:ff:ff:ff:ff:ff", "00:1a:2b:3c:4d:01", "192.168.1.50", "00:00:00:00:00:00", "192.168.1.1", false) },
  { ts: 1730419200.002, data: buildEthernetArp("00:50:56:c0:00:01", "00:1a:2b:3c:4d:01", "00:50:56:c0:00:01", "192.168.1.1", "00:1a:2b:3c:4d:01", "192.168.1.50", true) },
  { ts: 1730419200.05, data: buildEthernetArp("00:0c:29:8a:4f:1b", "00:1a:2b:3c:4d:01", "00:0c:29:8a:4f:1b", "192.168.1.1", "00:1a:2b:3c:4d:01", "192.168.1.50", true) },
  { ts: 1730419200.07, data: buildEthernetArp("00:0c:29:8a:4f:1b", "00:1a:2b:3c:4d:01", "00:0c:29:8a:4f:1b", "192.168.1.1", "00:1a:2b:3c:4d:01", "192.168.1.50", true) },
  { ts: 1730419200.09, data: buildEthernetArp("00:0c:29:8a:4f:1b", "00:1a:2b:3c:4d:01", "00:0c:29:8a:4f:1b", "192.168.1.1", "00:1a:2b:3c:4d:01", "192.168.1.50", true) },
  { ts: 1730419200.2, data: buildEthernetIpv4Tcp("00:1a:2b:3c:4d:01", "00:0c:29:8a:4f:1b", "192.168.1.50", "93.184.216.34", 52144, 80, 0x18, 1, 1, 64240, "GET /login HTTP/1.1\r\nHost: corp\r\n\r\n") },
];
const arpPcap = createPcapBytes(arpRecords);
fs.writeFileSync(path.join(dir, "1_arp_spoofing_mitm.pcap"), arpPcap);
fs.writeFileSync(path.join(pubDir, "1_arp_spoofing_mitm.pcap"), arpPcap);

// 2. SYN Stealth Port Scan capture
const synRecords = [];
const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080];
let t = 1730419210.0;
for (const p of ports) {
  t += 0.01;
  synRecords.push({ ts: t, data: buildEthernetIpv4Tcp("00:aa:bb:cc:dd:ee", "00:11:22:33:44:55", "10.0.0.88", "10.0.0.12", 45000 + p, p, 0x02, 1000 + p, 0, 1024) });
  t += 0.005;
  if (p === 80 || p === 443) {
    synRecords.push({ ts: t, data: buildEthernetIpv4Tcp("00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", "10.0.0.12", "10.0.0.88", p, 45000 + p, 0x12, 5000 + p, 1001 + p, 65535) });
  } else {
    synRecords.push({ ts: t, data: buildEthernetIpv4Tcp("00:11:22:33:44:55", "00:aa:bb:cc:dd:ee", "10.0.0.12", "10.0.0.88", p, 45000 + p, 0x14, 0, 1001 + p, 0) });
  }
}
const synPcap = createPcapBytes(synRecords);
fs.writeFileSync(path.join(dir, "2_syn_port_scan.pcap"), synPcap);
fs.writeFileSync(path.join(pubDir, "2_syn_port_scan.pcap"), synPcap);

// 3. TCP Retransmission Outage
const tcpRecords = [];
t = 1730419230.0;
for (let i = 0; i < 4; i++) {
  t += 0.05;
  tcpRecords.push({ ts: t, data: buildEthernetIpv4Tcp("00:11:22:33:44:55", "00:66:77:88:99:00", "192.168.1.50", "10.0.0.200", 49152, 443, 0x18, 10000 + i * 1400, 1, 65535, "Payload Data Chunk " + i) });
}
for (let i = 0; i < 5; i++) {
  t += 0.2;
  tcpRecords.push({ ts: t, data: buildEthernetIpv4Tcp("00:11:22:33:44:55", "00:66:77:88:99:00", "192.168.1.50", "10.0.0.200", 49152, 443, 0x18, 11400, 1, 65535, "Retransmitted Payload Data") });
}
for (let i = 0; i < 3; i++) {
  t += 0.1;
  tcpRecords.push({ ts: t, data: buildEthernetIpv4Tcp("00:66:77:88:99:00", "00:11:22:33:44:55", "10.0.0.200", "192.168.1.50", 443, 49152, 0x10, 1, 11400, 0) });
}
const tcpPcap = createPcapBytes(tcpRecords);
fs.writeFileSync(path.join(dir, "3_tcp_congestion_outage.pcap"), tcpPcap);
fs.writeFileSync(path.join(pubDir, "3_tcp_congestion_outage.pcap"), tcpPcap);

console.log("Successfully generated realistic binary sample .pcap captures!");
