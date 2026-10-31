"use client";

import { useState, useMemo } from "react";
import {
  Search,
  Layers,
  ArrowRight,
  Terminal,
} from "lucide-react";
import { Button, Chip, Panel, SectionTitle, Swatch, cn } from "./ui";
import { ParsedPacket } from "@/lib/engine/types";
import { formatBytes } from "@/lib/utils/formatters";

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

  const protocols = useMemo(() => {
    const list = new Set(packets.map((p) => p.protocol));
    return ["ALL", ...Array.from(list)];
  }, [packets]);

  const filteredPackets = useMemo(() => {
    return packets.filter((p) => {
      const matchProto = protocolFilter === "ALL" || p.protocol === protocolFilter;
      const q = search.toLowerCase();
      const matchSearch =
        !q ||
        p.frame_number.toString().includes(q) ||
        (p.source_ip && p.source_ip.toLowerCase().includes(q)) ||
        (p.destination_ip && p.destination_ip.toLowerCase().includes(q)) ||
        (p.info && p.info.toLowerCase().includes(q)) ||
        (p.dns_query && p.dns_query.toLowerCase().includes(q));

      return matchProto && matchSearch;
    });
  }, [packets, protocolFilter, search]);

  const inspectPacket = useMemo(() => {
    if (!activeFrame) return packets[0] || null;
    return packets.find((p) => p.frame_number === activeFrame) || packets[0] || null;
  }, [packets, activeFrame]);

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

  return (
    <div className="space-y-4">
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
                placeholder="Filter by IP, port, flag..."
                className="pl-8 pr-3 py-1.5 bg-sunk rounded-[10px] text-xs text-ink border border-rule focus:outline-none focus:border-brand w-48 sm:w-64"
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

      {/* Protocol Filter Tabs (Pill style) */}
      <div className="flex flex-wrap items-center gap-1.5 pb-1">
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
    </div>
  );
}
