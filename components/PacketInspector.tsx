"use client";

import { useState, useMemo } from "react";
import {
  Search,
  Layers,
  ArrowRight,
  Terminal,
  Filter,
  MessageSquare,
  X,
  Copy,
  Check,
  Code2,
} from "lucide-react";
import { Button, Chip, Panel, SectionTitle, Swatch, cn } from "./ui";
import { ParsedPacket } from "@/lib/engine/types";
import { formatBytes } from "@/lib/utils/formatters";
import { toast } from "sonner";

interface PacketInspectorProps {
  packets: ParsedPacket[];
  selectedPacketFrame?: number | null;
}

/** Formats a raw hex string into standard 16-bytes-per-line Wireshark/tcpdump hex + ASCII dump */
function formatHexDump(hexString?: string): string {
  if (!hexString) return "0000   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|";
  const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, "");
  if (!cleanHex) return "0000   00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|";
  
  const lines: string[] = [];
  for (let i = 0; i < cleanHex.length; i += 32) {
    const chunk = cleanHex.slice(i, i + 32);
    const offset = (i / 2).toString(16).padStart(4, "0");
    
    const bytes: string[] = [];
    let ascii = "";
    for (let j = 0; j < chunk.length; j += 2) {
      const byteHex = chunk.slice(j, j + 2);
      bytes.push(byteHex);
      const code = parseInt(byteHex, 16);
      ascii += (code >= 32 && code <= 126) ? String.fromCharCode(code) : ".";
    }
    
    const part1 = bytes.slice(0, 8).join(" ");
    const part2 = bytes.slice(8, 16).join(" ");
    const padded1 = part1.padEnd(23, " ");
    const padded2 = part2.padEnd(23, " ");
    lines.push(`${offset}   ${padded1}  ${padded2}   |${ascii.padEnd(16, " ")}|`);
  }
  return lines.join("\n");
}

export function PacketInspector({
  packets,
  selectedPacketFrame,
}: PacketInspectorProps) {
  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [activeFilterTag, setActiveFilterTag] = useState<{ type: "IP" | "PORT" | "PROTO"; value: string } | null>(null);
  const [activeTab, setActiveTab] = useState<"LAYERS" | "HEX_DUMP">("LAYERS");
  const [activeFrame, setActiveFrame] = useState<number | null>(
    selectedPacketFrame || (packets.length > 0 ? packets[0].frame_number : null)
  );
  const [isFollowStreamOpen, setIsFollowStreamOpen] = useState(false);
  const [copiedStream, setCopiedStream] = useState(false);
  const [copiedHex, setCopiedHex] = useState(false);

  const protocols = useMemo(() => {
    const list = new Set(packets.map((p) => p.protocol));
    return ["ALL", ...Array.from(list)];
  }, [packets]);

  // Quick Display Filters (Wireshark-style)
  const quickFilters = [
    { label: "tcp.syn", filter: "syn" },
    { label: "tcp.rst", filter: "rst" },
    { label: "retransmission", filter: "retransmission" },
    { label: "arp", filter: "arp" },
    { label: "dns", filter: "dns" },
    { label: "icmp", filter: "icmp" },
  ];

  const applyQuickFilter = (qf: string) => {
    if (search === qf) {
      setSearch("");
    } else {
      setSearch(qf);
    }
  };

  const filteredPackets = useMemo(() => {
    return packets.filter((p) => {
      // Check active filter tag (Click-to-Filter)
      if (activeFilterTag) {
        if (activeFilterTag.type === "IP") {
          const matchIp = p.source_ip === activeFilterTag.value || p.destination_ip === activeFilterTag.value;
          if (!matchIp) return false;
        } else if (activeFilterTag.type === "PORT") {
          const matchPort = p.source_port?.toString() === activeFilterTag.value || p.destination_port?.toString() === activeFilterTag.value;
          if (!matchPort) return false;
        } else if (activeFilterTag.type === "PROTO") {
          if (p.protocol !== activeFilterTag.value) return false;
        }
      }

      const matchProto = protocolFilter === "ALL" || p.protocol === protocolFilter;
      const q = search.trim().toLowerCase();

      if (!q) return matchProto;

      // Wireshark quick filter keywords
      if (q === "syn") return matchProto && p.tcp_flags?.syn;
      if (q === "rst") return matchProto && p.tcp_flags?.rst;
      if (q === "retransmission") return matchProto && p.info.toLowerCase().includes("retransmission");
      if (q === "arp") return matchProto && p.protocol === "ARP";
      if (q === "dns") return matchProto && p.protocol === "DNS";
      if (q === "icmp") return matchProto && p.protocol === "ICMP";

      // Free-text search
      const matchSearch =
        p.frame_number.toString().includes(q) ||
        (p.source_ip && p.source_ip.toLowerCase().includes(q)) ||
        (p.destination_ip && p.destination_ip.toLowerCase().includes(q)) ||
        (p.source_port && p.source_port.toString().includes(q)) ||
        (p.destination_port && p.destination_port.toString().includes(q)) ||
        (p.info && p.info.toLowerCase().includes(q)) ||
        (p.dns_query && p.dns_query.toLowerCase().includes(q));

      return matchProto && matchSearch;
    });
  }, [packets, protocolFilter, search, activeFilterTag]);

  const inspectPacket = useMemo(() => {
    if (!activeFrame) return packets[0] || null;
    return packets.find((p) => p.frame_number === activeFrame) || packets[0] || null;
  }, [packets, activeFrame]);

  // Reconstruct TCP Conversation Stream for active packet
  const tcpStreamConversation = useMemo(() => {
    if (!inspectPacket || inspectPacket.protocol !== "TCP" || !inspectPacket.source_ip || !inspectPacket.destination_ip) {
      return null;
    }
    const ip1 = inspectPacket.source_ip;
    const ip2 = inspectPacket.destination_ip;
    const port1 = inspectPacket.source_port;
    const port2 = inspectPacket.destination_port;

    const streamPackets = packets.filter(p => {
      if (p.protocol !== "TCP") return false;
      const direct = (p.source_ip === ip1 && p.destination_ip === ip2 && p.source_port === port1 && p.destination_port === port2);
      const reverse = (p.source_ip === ip2 && p.destination_ip === ip1 && p.source_port === port2 && p.destination_port === port1);
      return direct || reverse;
    });

    return {
      endpointA: `${ip1}:${port1}`,
      endpointB: `${ip2}:${port2}`,
      packets: streamPackets,
    };
  }, [packets, inspectPacket]);

  const getProtocolColor = (proto: string) => {
    switch (proto) {
      case "TCP":
        return "var(--color-c-tcp)";
      case "DNS":
        return "var(--color-c-dns)";
      case "ARP":
        return "var(--color-c-routing)";
      case "ICMP":
        return "var(--color-c-latency)";
      default:
        return "var(--color-c-other)";
    }
  };

  const copyStreamText = () => {
    if (!tcpStreamConversation) return;
    const text = tcpStreamConversation.packets
      .map(p => `[${p.source_ip}:${p.source_port} -> ${p.destination_ip}:${p.destination_port}] ${p.payload_preview || p.info}`)
      .join("\n");
    navigator.clipboard.writeText(text);
    setCopiedStream(true);
    toast.success("TCP Stream conversation copied!");
    setTimeout(() => setCopiedStream(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header with Search and Clear */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-ink">
            Packet Stream ({filteredPackets.length} of {packets.length} frames)
          </h2>
          <p className="text-sm text-ink-2 mt-0.5">
            Deep frame analysis, protocol layer decoding, and bounds-checked hex viewer
          </p>
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          <div className="relative flex-1 sm:flex-initial">
            <Search
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3"
            />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IP, port, flag..."
              className="pl-9 pr-3 py-2 bg-sunk rounded-xl text-sm text-ink border border-rule focus:outline-none focus:border-brand w-full sm:w-72 font-mono"
            />
          </div>
          {search && (
            <Button variant="ghost" size="sm" onClick={() => setSearch("")}>
              Clear
            </Button>
          )}
        </div>
      </div>

      {/* Protocol & Quick Filter Bar */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-raised border border-rule rounded-xl">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs uppercase font-bold text-ink-3 mr-1">Protocols:</span>
            {protocols.map((proto) => (
              <button
                key={proto}
                type="button"
                onClick={() => setProtocolFilter(proto)}
                className={cn(
                  "px-3 py-1 rounded-full text-xs font-semibold border transition-colors cursor-pointer inline-flex items-center gap-1.5",
                  protocolFilter === proto
                    ? "bg-brand text-on-brand border-brand"
                    : "bg-raised text-ink-2 border-rule hover:border-rule-strong hover:bg-sunk"
                )}
              >
                {proto !== "ALL" && <Swatch color={getProtocolColor(proto)} className="w-2 h-2 rounded-full" />}
                <span>{proto}</span>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs uppercase font-bold text-ink-3 mr-1">Quick Filters:</span>
            {quickFilters.map((qf) => (
              <button
                key={qf.filter}
                onClick={() => applyQuickFilter(qf.filter)}
                className={cn(
                  "px-2.5 py-1 rounded-lg text-xs font-mono border transition-colors",
                  search === qf.filter
                    ? "bg-ink text-canvas border-ink font-bold"
                    : "bg-sunk text-ink-2 border-rule-soft hover:bg-raised"
                )}
              >
                {qf.label}
              </button>
            ))}
          </div>
        </div>

        {/* Active Click-to-Filter Pill Bar */}
        {activeFilterTag && (
          <div className="flex items-center gap-2.5 px-4 py-2.5 bg-brand-soft border border-brand/30 rounded-xl text-xs font-mono text-brand font-semibold animate-in fade-in">
            <span>Filter Active:</span>
            <span className="bg-raised px-2.5 py-1 rounded-md border border-brand/40 inline-flex items-center gap-2 text-ink">
              <span>{activeFilterTag.type} == &apos;{activeFilterTag.value}&apos;</span>
              <button
                onClick={() => setActiveFilterTag(null)}
                className="hover:text-flag transition-colors p-0.5 rounded cursor-pointer"
                title="Remove filter"
              >
                <X size={12} />
              </button>
            </span>
            <button
              onClick={() => { setActiveFilterTag(null); setSearch(""); setProtocolFilter("ALL"); }}
              className="ml-auto text-xs text-ink-3 hover:text-ink underline cursor-pointer"
            >
              Reset All Filters
            </button>
          </div>
        )}
      </div>

      {/* Symmetric Two-Column Layout (50/50 Grid) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        {/* Left: Symmetric Dense Table (Equal Height) */}
        <Panel className="p-0 overflow-hidden flex flex-col h-[580px] border border-rule shadow-xs">
          <div className="overflow-y-auto flex-1 font-mono text-sm">
            <table className="chart w-full">
              <thead>
                <tr>
                  <th className="w-12">#</th>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  <th>Len</th>
                  <th>Info</th>
                </tr>
              </thead>
              <tbody>
                {filteredPackets.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-16 text-ink-3 font-sans text-sm">
                      No frames matched search query or active filter.
                    </td>
                  </tr>
                ) : (
                  filteredPackets.map((pkt) => {
                    const isActive = inspectPacket?.frame_number === pkt.frame_number;
                    const isRetrans = pkt.info.includes("Retransmission");
                    const isRst = pkt.tcp_flags?.rst;

                    return (
                      <tr
                        key={pkt.frame_number}
                        onClick={() => setActiveFrame(pkt.frame_number)}
                        className={cn(
                          "cursor-pointer select-none transition-colors",
                          isActive
                            ? "bg-brand-soft font-semibold text-brand"
                            : isRetrans
                            ? "bg-warn-soft/40"
                            : isRst
                            ? "bg-flag-soft/30"
                            : "hover:bg-sunk/50"
                        )}
                      >
                        <td className="font-semibold text-ink-3">{pkt.frame_number}</td>
                        <td className="text-ink-2">{pkt.timestamp.toFixed(3)}</td>
                        <td
                          className="text-ink truncate max-w-[130px] hover:text-brand hover:underline"
                          title="Click to filter by source IP"
                          onClick={(e) => {
                            if (pkt.source_ip) {
                              e.stopPropagation();
                              setActiveFilterTag({ type: "IP", value: pkt.source_ip });
                            }
                          }}
                        >
                          {pkt.source_ip || pkt.source_mac || "Local"}
                        </td>
                        <td
                          className="text-ink truncate max-w-[130px] hover:text-brand hover:underline"
                          title="Click to filter by destination IP"
                          onClick={(e) => {
                            if (pkt.destination_ip) {
                              e.stopPropagation();
                              setActiveFilterTag({ type: "IP", value: pkt.destination_ip });
                            }
                          }}
                        >
                          {pkt.destination_ip || pkt.destination_mac || "Broadcast"}
                        </td>
                        <td
                          className="hover:text-brand"
                          title="Click to filter by protocol"
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveFilterTag({ type: "PROTO", value: pkt.protocol });
                          }}
                        >
                          <div className="flex items-center gap-1.5">
                            <Swatch color={getProtocolColor(pkt.protocol)} className="w-2 h-2 rounded-full" />
                            <span className="font-semibold text-xs">{pkt.protocol}</span>
                          </div>
                        </td>
                        <td className="text-ink-2">{pkt.length}</td>
                        <td className="text-ink-2 truncate max-w-[200px]" title={pkt.info}>
                          {pkt.info}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        {/* Right: Symmetric Protocol Layers & Hex Dump (Equal Height) */}
        <Panel className="p-6 flex flex-col h-[580px] overflow-hidden border border-rule shadow-xs">
          {inspectPacket ? (
            <div className="flex flex-col h-full overflow-hidden">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-rule mb-4">
                <div className="flex items-center gap-3">
                  <span className="font-extrabold text-base text-ink font-mono">
                    Frame #{inspectPacket.frame_number}
                  </span>
                  <Chip tone="brand">
                    <Swatch color={getProtocolColor(inspectPacket.protocol)} className="w-2 h-2 rounded-full" />
                    {inspectPacket.protocol}
                  </Chip>
                  <span className="text-xs text-ink-3 font-mono">{inspectPacket.length} bytes</span>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex items-center gap-1 p-1 bg-sunk rounded-lg border border-rule text-xs">
                    <button
                      type="button"
                      onClick={() => setActiveTab("LAYERS")}
                      className={cn(
                        "px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer",
                        activeTab === "LAYERS" ? "bg-raised text-ink shadow-xs" : "text-ink-2 hover:text-ink"
                      )}
                    >
                      Layers
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("HEX_DUMP")}
                      className={cn(
                        "px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer",
                        activeTab === "HEX_DUMP" ? "bg-raised text-ink shadow-xs" : "text-ink-2 hover:text-ink"
                      )}
                    >
                      Hex Dump
                    </button>
                  </div>

                  {inspectPacket.protocol === "TCP" && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setIsFollowStreamOpen(true)}
                    >
                      <MessageSquare size={13} />
                      <span className="hidden sm:inline">Follow Stream</span>
                    </Button>
                  )}
                </div>
              </div>

              {activeTab === "HEX_DUMP" ? (
                <div className="flex-1 flex flex-col overflow-hidden space-y-3">
                  <div className="flex items-center justify-between text-xs text-ink-2 px-1">
                    <span>Wireshark Hex Byte Grid (16-byte alignment &bull; ASCII)</span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        const dump = formatHexDump(inspectPacket.payload_hex);
                        navigator.clipboard.writeText(dump);
                        setCopiedHex(true);
                        toast.success("Hex dump copied to clipboard!");
                        setTimeout(() => setCopiedHex(false), 2000);
                      }}
                    >
                      {copiedHex ? <Check size={12} /> : <Copy size={12} />}
                      <span>{copiedHex ? "Copied" : "Copy Hex"}</span>
                    </Button>
                  </div>
                  <pre className="p-4 rounded-xl bg-sunk border border-rule font-mono text-xs text-ink overflow-auto flex-1 select-text leading-relaxed whitespace-pre">
                    {formatHexDump(inspectPacket.payload_hex)}
                  </pre>
                </div>
              ) : (
                <div className="overflow-y-auto flex-1 space-y-4 pr-1 text-sm">
                  {/* Frame Metadata */}
                  <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1 font-mono">
                    <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider mb-1">
                      Frame Metadata
                    </span>
                    <div className="text-ink-2">Timestamp: {inspectPacket.timestamp_iso || inspectPacket.timestamp}</div>
                    <div className="text-ink-2">Wire Length: {inspectPacket.length} bytes ({formatBytes(inspectPacket.length)})</div>
                  </div>

                  {/* Layer 2: Ethernet */}
                  <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1 font-mono">
                    <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider mb-1">
                      Ethernet II Layer
                    </span>
                    <div className="text-ink-2">Source MAC: {inspectPacket.source_mac || "00:00:00:00:00:00"}</div>
                    <div className="text-ink-2">Destination MAC: {inspectPacket.destination_mac || "ff:ff:ff:ff:ff:ff"}</div>
                    {inspectPacket.ether_type && <div className="text-ink-2">EtherType: {inspectPacket.ether_type}</div>}
                  </div>

                  {/* Layer 3: Network */}
                  <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1 font-mono">
                    <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider mb-1">
                      Network Layer ({inspectPacket.protocol === "ARP" ? "ARP" : `IPv${inspectPacket.ip_version || 4}`})
                    </span>
                    {inspectPacket.source_ip && <div className="text-ink-2">Source IP: {inspectPacket.source_ip}</div>}
                    {inspectPacket.destination_ip && <div className="text-ink-2">Destination IP: {inspectPacket.destination_ip}</div>}
                    {inspectPacket.arp_opcode && (
                      <>
                        <div className="text-ink-2">ARP Opcode: {inspectPacket.arp_opcode}</div>
                        <div className="text-ink-2">Sender IP: {inspectPacket.arp_sender_ip} ({inspectPacket.arp_sender_mac})</div>
                        <div className="text-ink-2">Target IP: {inspectPacket.arp_target_ip} ({inspectPacket.arp_target_mac})</div>
                      </>
                    )}
                  </div>

                  {/* Layer 4: Transport */}
                  {(inspectPacket.source_port || inspectPacket.icmp_type !== undefined) && (
                    <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1 font-mono">
                      <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider mb-1">
                        Transport Layer ({inspectPacket.protocol})
                      </span>
                      {inspectPacket.source_port && <div className="text-ink-2">Source Port: {inspectPacket.source_port}</div>}
                      {inspectPacket.destination_port && <div className="text-ink-2">Destination Port: {inspectPacket.destination_port}</div>}
                      {inspectPacket.tcp_seq !== undefined && <div className="text-ink-2">Seq: {inspectPacket.tcp_seq} | Ack: {inspectPacket.tcp_ack}</div>}
                      {inspectPacket.tcp_window_size !== undefined && <div className="text-ink-2">Window Size: {inspectPacket.tcp_window_size}</div>}
                      {inspectPacket.tcp_flags && (
                        <div className="text-ink font-semibold">
                          Flags:{" "}
                          {Object.entries(inspectPacket.tcp_flags)
                            .filter(([_, v]) => v)
                            .map(([k]) => k.toUpperCase())
                            .join(", ") || "NONE"}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Layer 7: Application */}
                  {(inspectPacket.dns_query || inspectPacket.dhcp_msg_type) && (
                    <div className="p-4 rounded-xl bg-sunk/60 border border-rule space-y-1 font-mono">
                      <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider mb-1">
                        Application Payload
                      </span>
                      {inspectPacket.dns_query && (
                        <>
                          <div className="text-ink-2">DNS Query: {inspectPacket.dns_query} ({inspectPacket.dns_qtype || "A"})</div>
                          <div className="text-ink-2">Response Code: {inspectPacket.dns_response_code ?? "Query"}</div>
                        </>
                      )}
                      {inspectPacket.dhcp_msg_type && (
                        <div className="text-ink-2">DHCP Type: {inspectPacket.dhcp_msg_type}</div>
                      )}
                    </div>
                  )}

                  {/* Safe Payload Hex Dump Preview */}
                  <div className="p-4 rounded-xl bg-sunk/80 border border-rule space-y-2">
                    <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
                      Safe Payload Preview
                    </span>
                    <pre className="p-3 rounded-lg bg-raised border border-rule font-mono text-xs text-ink overflow-x-auto whitespace-pre leading-relaxed select-text">
                      {inspectPacket.payload_preview || inspectPacket.payload_hex || "No raw payload bytes in this frame."}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-sm text-ink-3">
              Select a frame from the packet stream to inspect protocol layers.
            </div>
          )}
        </Panel>
      </div>

      {/* Follow TCP Stream Modal */}
      {isFollowStreamOpen && tcpStreamConversation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-raised border border-rule rounded-2xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-rule bg-sunk/60">
              <div className="flex items-center gap-2.5">
                <MessageSquare size={18} className="text-brand" />
                <h3 className="font-bold text-base text-ink font-mono">
                  Follow TCP Stream: {tcpStreamConversation.endpointA} &lt;-&gt; {tcpStreamConversation.endpointB}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={copyStreamText}>
                  {copiedStream ? <Check size={14} /> : <Copy size={14} />}
                  <span>Copy Stream</span>
                </Button>
                <button
                  onClick={() => setIsFollowStreamOpen(false)}
                  className="p-1.5 rounded-full hover:bg-raised text-ink-2 hover:text-ink transition-colors"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            {/* Conversation Flow Reconstructed */}
            <div className="p-6 overflow-y-auto flex-1 space-y-3 font-mono text-sm bg-canvas">
              <div className="p-3 bg-sunk rounded-xl text-xs text-ink-2 mb-3">
                Reconstructed bidirectional conversational stream ({tcpStreamConversation.packets.length} frames). Client requests highlighted in blue, server responses in green/amber.
              </div>

              {tcpStreamConversation.packets.map((p) => {
                const isClient = p.source_ip === inspectPacket?.source_ip;
                return (
                  <div
                    key={p.frame_number}
                    className={cn(
                      "p-3.5 rounded-xl border text-sm leading-relaxed",
                      isClient
                        ? "bg-blue-500/5 border-blue-500/20 text-blue-950 dark:text-blue-200"
                        : "bg-emerald-500/5 border-emerald-500/20 text-emerald-950 dark:text-emerald-200"
                    )}
                  >
                    <div className="flex items-center justify-between text-xs font-bold opacity-75 mb-1.5">
                      <span>Frame #{p.frame_number} • {p.source_ip}:{p.source_port} &rarr; {p.destination_ip}:{p.destination_port}</span>
                      <span>{p.length} bytes</span>
                    </div>
                    <div className="font-mono whitespace-pre-wrap select-text">
                      {p.payload_preview || p.info}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-rule bg-sunk/60 flex items-center justify-between text-xs text-ink-2">
              <span>Safely sanitized against code execution and malicious payloads.</span>
              <Button variant="secondary" size="sm" onClick={() => setIsFollowStreamOpen(false)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
