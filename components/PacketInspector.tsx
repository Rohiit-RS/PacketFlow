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
  Activity,
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

export function PacketInspector({
  packets,
  selectedPacketFrame,
}: PacketInspectorProps) {
  const [search, setSearch] = useState("");
  const [protocolFilter, setProtocolFilter] = useState<string>("ALL");
  const [activeFrame, setActiveFrame] = useState<number | null>(
    selectedPacketFrame || (packets.length > 0 ? packets[0].frame_number : null)
  );
  const [isFollowStreamOpen, setIsFollowStreamOpen] = useState(false);
  const [copiedStream, setCopiedStream] = useState(false);

  const protocols = useMemo(() => {
    const list = new Set(packets.map((p) => p.protocol));
    return ["ALL", ...Array.from(list)];
  }, [packets]);

  // Quick Display Filters (Wireshark-style)
  const quickFilters = [
    { label: "tcp.flags.syn == 1", filter: "syn" },
    { label: "tcp.flags.reset == 1", filter: "rst" },
    { label: "retransmission", filter: "retransmission" },
    { label: "arp", filter: "arp" },
    { label: "dns", filter: "dns" },
    { label: "icmp", filter: "icmp" },
    { label: "len > 100", filter: "len100" },
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
      if (q === "len100") return matchProto && p.length > 100;

      // Free-text search
      const matchSearch =
        p.frame_number.toString().includes(q) ||
        (p.source_ip && p.source_ip.toLowerCase().includes(q)) ||
        (p.destination_ip && p.destination_ip.toLowerCase().includes(q)) ||
        (p.source_port && p.source_port.toString().includes(q)) ||
        (p.destination_port && p.destination_port.toString().includes(q)) ||
        (p.info && p.info.toLowerCase().includes(q)) ||
        (p.dns_query && p.dns_query.toLowerCase().includes(q)) ||
        (p.payload_preview && p.payload_preview.toLowerCase().includes(q));

      return matchProto && matchSearch;
    });
  }, [packets, protocolFilter, search]);

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

  // Mini timeline histogram
  const timelineHistogram = useMemo(() => {
    if (packets.length === 0) return [];
    const minTime = packets[0].timestamp;
    const maxTime = packets[packets.length - 1].timestamp;
    const duration = Math.max(0.1, maxTime - minTime);
    const bins = 16;
    const binWidth = duration / bins;

    const counts = Array.from({ length: bins }, () => 0);
    packets.forEach(p => {
      const idx = Math.min(bins - 1, Math.floor((p.timestamp - minTime) / binWidth));
      counts[idx]++;
    });
    const maxCount = Math.max(1, ...counts);
    return counts.map((count, i) => ({
      count,
      pct: (count / maxCount) * 100,
      time: (minTime + i * binWidth).toFixed(2),
    }));
  }, [packets]);

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
    <div className="space-y-4">
      {/* Header with Search and Clear */}
      <SectionTitle
        sub="Deep frame analysis, protocol layer decoding, and bounds-checked hex payload viewer"
        action={
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search
                size={14}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3"
              />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Wireshark filter or IP, port, flag..."
                className="pl-8 pr-3 py-1.5 bg-sunk rounded-[10px] text-xs text-ink border border-rule focus:outline-none focus:border-brand w-56 sm:w-72 font-mono"
              />
            </div>
            {search && (
              <Button variant="ghost" size="sm" onClick={() => setSearch("")}>
                Clear
              </Button>
            )}
          </div>
        }
      >
        Packet Stream ({filteredPackets.length} / {packets.length})
      </SectionTitle>

      {/* Mini Visual Traffic Timeline */}
      <div className="p-3 bg-raised border border-rule rounded-[10px] flex items-center justify-between gap-4">
        <div className="flex items-center gap-2 text-xs font-semibold text-ink-2 shrink-0">
          <Activity size={14} className="text-brand" />
          <span>Traffic Burst Histogram</span>
        </div>

        <div className="flex items-end gap-1 flex-1 h-6 px-2">
          {timelineHistogram.map((bin, i) => (
            <div
              key={i}
              className="flex-1 bg-brand/30 hover:bg-brand rounded-t-[2px] transition-colors cursor-pointer"
              style={{ height: `${Math.max(15, bin.pct)}%` }}
              title={`Time ${bin.time}s: ${bin.count} packets`}
            />
          ))}
        </div>

        <div className="text-[11px] font-mono text-ink-3 shrink-0">
          {packets.length > 0 ? `${packets[0].timestamp.toFixed(2)}s - ${packets[packets.length - 1].timestamp.toFixed(2)}s` : ""}
        </div>
      </div>

      {/* Wireshark Quick Filter Pills */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
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
              {proto !== "ALL" && <Swatch color={getProtocolColor(proto)} />}
              <span>{proto}</span>
            </button>
          ))}
        </div>

        {/* Display Filter Syntax Pills */}
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-[10px] uppercase font-bold text-ink-3 mr-1">Quick Filters:</span>
          {quickFilters.map((qf) => (
            <button
              key={qf.filter}
              onClick={() => applyQuickFilter(qf.filter)}
              className={cn(
                "px-2 py-0.5 rounded-[6px] text-[10px] font-mono border transition-colors",
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

      {/* Two Column Layout: Dense Swiss Table & Frame Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Dense Swiss Table */}
        <Panel className="lg:col-span-7 overflow-hidden flex flex-col h-[520px]">
          <div className="overflow-y-auto flex-1 font-mono text-xs">
            <table className="chart">
              <thead>
                <tr>
                  <th className="w-12">#</th>
                  <th>Time (s)</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Proto</th>
                  <th>Bytes</th>
                  <th>Protocol Info</th>
                </tr>
              </thead>
              <tbody>
                {filteredPackets.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-12 text-ink-3 font-sans text-xs">
                      No packets matched search filter.
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
                            : ""
                        )}
                      >
                        <td className="font-sans font-semibold text-ink-3">
                          {pkt.frame_number}
                        </td>
                        <td className="text-ink-2">
                          {pkt.timestamp.toFixed(3)}
                        </td>
                        <td className="text-ink truncate max-w-[120px]">
                          {pkt.source_ip || pkt.source_mac || "Local"}
                        </td>
                        <td className="text-ink truncate max-w-[120px]">
                          {pkt.destination_ip || pkt.destination_mac || "Broadcast"}
                        </td>
                        <td>
                          <div className="flex items-center gap-1.5">
                            <Swatch color={getProtocolColor(pkt.protocol)} />
                            <span className="font-sans text-[11px] font-semibold">{pkt.protocol}</span>
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

        {/* Right: Decoded Protocol Layers & Hex Dump */}
        <Panel className="lg:col-span-5 p-4 flex flex-col h-[520px] overflow-hidden">
          {inspectPacket ? (
            <div className="flex flex-col h-full overflow-hidden">
              <div className="flex items-center justify-between pb-3 border-b border-rule mb-3">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-sm text-ink font-mono">
                    Frame #{inspectPacket.frame_number}
                  </span>
                  <Chip tone="brand" className="text-xs">
                    <Swatch color={getProtocolColor(inspectPacket.protocol)} />
                    {inspectPacket.protocol}
                  </Chip>
                  <span className="text-xs text-ink-3">{inspectPacket.length} bytes</span>
                </div>

                {inspectPacket.protocol === "TCP" && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setIsFollowStreamOpen(true)}
                    className="text-[11px] h-7 px-2"
                  >
                    <MessageSquare size={12} />
                    <span>Follow Stream</span>
                  </Button>
                )}
              </div>

              <div className="overflow-y-auto flex-1 space-y-3 pr-1 text-xs">
                {/* Frame Header */}
                <div className="p-3 rounded-[10px] bg-sunk/60 border border-rule space-y-1 font-mono">
                  <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
                    Frame Metadata
                  </span>
                  <div className="text-ink-2">Timestamp: {inspectPacket.timestamp_iso || inspectPacket.timestamp}</div>
                  <div className="text-ink-2">Wire Length: {inspectPacket.length} bytes ({formatBytes(inspectPacket.length)})</div>
                </div>

                {/* Layer 2: Ethernet II */}
                <div className="p-3 rounded-[10px] bg-sunk/60 border border-rule space-y-1 font-mono">
                  <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
                    Ethernet II Layer
                  </span>
                  <div className="text-ink-2">Source MAC: {inspectPacket.source_mac || "00:00:00:00:00:00"}</div>
                  <div className="text-ink-2">Destination MAC: {inspectPacket.destination_mac || "ff:ff:ff:ff:ff:ff"}</div>
                  {inspectPacket.ether_type && <div className="text-ink-2">EtherType: {inspectPacket.ether_type}</div>}
                </div>

                {/* Layer 3: Network */}
                <div className="p-3 rounded-[10px] bg-sunk/60 border border-rule space-y-1 font-mono">
                  <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
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
                  <div className="p-3 rounded-[10px] bg-sunk/60 border border-rule space-y-1 font-mono">
                    <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
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
                    {inspectPacket.icmp_description && <div className="text-ink-2">{inspectPacket.icmp_description}</div>}
                  </div>
                )}

                {/* Layer 7: Application */}
                {(inspectPacket.dns_query || inspectPacket.dhcp_msg_type) && (
                  <div className="p-3 rounded-[10px] bg-sunk/60 border border-rule space-y-1 font-mono">
                    <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
                      Application Payload
                    </span>
                    {inspectPacket.dns_query && (
                      <>
                        <div className="text-ink-2">DNS Query: {inspectPacket.dns_query} ({inspectPacket.dns_qtype || "A"})</div>
                        <div className="text-ink-2">Response Code: {inspectPacket.dns_response_code ?? "Query"}</div>
                      </>
                    )}
                    {inspectPacket.dhcp_msg_type && (
                      <>
                        <div className="text-ink-2">DHCP Type: {inspectPacket.dhcp_msg_type}</div>
                        {inspectPacket.dhcp_server_id && <div className="text-ink-2">Server ID: {inspectPacket.dhcp_server_id}</div>}
                      </>
                    )}
                  </div>
                )}

                {/* Safe Payload Hex Dump */}
                <div className="p-3 rounded-[10px] bg-sunk/80 border border-rule space-y-1.5">
                  <span className="font-sans font-bold text-xs text-ink-2 block uppercase tracking-wider">
                    Safe Payload Hex &amp; ASCII Viewer
                  </span>
                  <pre className="p-2.5 rounded-[8px] bg-raised border border-rule font-mono text-[10px] text-ink overflow-x-auto whitespace-pre leading-relaxed select-text">
                    {inspectPacket.payload_hex || "No raw payload bytes in this frame."}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-ink-3">
              Select a frame from the packet stream to inspect protocol layers.
            </div>
          )}
        </Panel>
      </div>

      {/* Follow TCP Stream Modal */}
      {isFollowStreamOpen && tcpStreamConversation && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-raised border border-rule rounded-card max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-rule bg-sunk/60">
              <div className="flex items-center gap-2">
                <MessageSquare size={16} className="text-brand" />
                <h3 className="font-bold text-sm text-ink font-mono">
                  Follow TCP Stream: {tcpStreamConversation.endpointA} &lt;-&gt; {tcpStreamConversation.endpointB}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={copyStreamText}>
                  {copiedStream ? <Check size={13} /> : <Copy size={13} />}
                  <span>Copy</span>
                </Button>
                <button
                  onClick={() => setIsFollowStreamOpen(false)}
                  className="p-1.5 rounded-full hover:bg-raised text-ink-2 hover:text-ink transition-colors"
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Conversation Flow Reconstructed */}
            <div className="p-4 overflow-y-auto flex-1 space-y-3 font-mono text-xs bg-canvas">
              <div className="p-2 bg-sunk rounded text-[11px] text-ink-2">
                Reconstructed bidirectional conversational stream ({tcpStreamConversation.packets.length} frames). Client requests highlighted in blue, server responses in green/amber.
              </div>

              {tcpStreamConversation.packets.map((p) => {
                const isClient = p.source_ip === inspectPacket?.source_ip;
                return (
                  <div
                    key={p.frame_number}
                    className={cn(
                      "p-3 rounded-[8px] border text-xs leading-relaxed",
                      isClient
                        ? "bg-blue-500/5 border-blue-500/20 text-blue-950 dark:text-blue-200"
                        : "bg-emerald-500/5 border-emerald-500/20 text-emerald-950 dark:text-emerald-200"
                    )}
                  >
                    <div className="flex items-center justify-between text-[10px] font-bold opacity-75 mb-1">
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
            <div className="p-3 border-t border-rule bg-sunk/60 flex items-center justify-between text-xs text-ink-2">
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
