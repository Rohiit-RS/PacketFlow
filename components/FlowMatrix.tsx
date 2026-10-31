"use client";

import { useState } from "react";
import { ArrowDownUp, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Panel, SectionTitle, Chip, Swatch, cn } from "./ui";
import { ConversationFlow } from "@/lib/engine/types";
import { formatBytes, formatDuration } from "@/lib/utils/formatters";

interface FlowMatrixProps {
  flows: ConversationFlow[];
}

export function FlowMatrix({ flows }: FlowMatrixProps) {
  const [filterState, setFilterState] = useState<string>("ALL");

  const filteredFlows = flows.filter((f) => {
    if (filterState === "ALL") return true;
    return f.state === filterState;
  });

  return (
    <div className="space-y-4">
      <SectionTitle
        sub="Bidirectional conversation flows reconstructed from packet headers and TCP sequence space"
        action={
          <div className="flex items-center gap-1.5 p-1 bg-sunk rounded-full border border-rule text-xs">
            {["ALL", "ESTABLISHED", "HALF_OPEN", "RESET"].map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => setFilterState(st)}
                className={cn(
                  "px-3 py-1 rounded-full font-semibold cursor-pointer transition-colors text-xs",
                  filterState === st
                    ? "bg-brand text-on-brand shadow-xs"
                    : "text-ink-2 hover:text-ink hover:bg-raised"
                )}
              >
                {st}
              </button>
            ))}
          </div>
        }
      >
        Active Conversations &amp; Flow Matrix ({flows.length})
      </SectionTitle>

      <Panel className="overflow-hidden border border-rule shadow-xs">
        <div className="overflow-x-auto font-mono text-sm max-h-[520px] overflow-y-auto">
          <table className="chart">
            <thead>
              <tr>
                <th>Flow Endpoints</th>
                <th>Protocol</th>
                <th>Packets</th>
                <th>Total Volume</th>
                <th>Duration</th>
                <th>RTT Latency</th>
                <th>Retransmissions</th>
                <th>Connection State</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-ink-3 font-sans">
                    No flows matched filter ({filterState}).
                  </td>
                </tr>
              ) : (
                filteredFlows.map((flow) => {
                  const isReset = flow.state === "RESET";
                  const isHalfOpen = flow.state === "HALF_OPEN";

                  return (
                    <tr key={flow.id} className="hover:bg-sunk/50 transition-colors">
                      <td className="font-semibold text-ink">
                        <div className="flex items-center gap-1.5">
                          <Swatch color="var(--color-c-tcp)" />
                          <span className="truncate max-w-[150px]">{flow.source}</span>
                          <span className="text-ink-3">&harr;</span>
                          <span className="truncate max-w-[150px]">{flow.destination}</span>
                        </div>
                      </td>
                      <td>
                        <span className="font-sans font-semibold text-xs text-ink-2">
                          {flow.protocol}
                        </span>
                      </td>
                      <td className="text-ink font-semibold">{flow.packets_count}</td>
                      <td className="text-ink-2">{formatBytes(flow.bytes_count)}</td>
                      <td className="text-ink-2">{formatDuration(flow.duration_sec)}</td>
                      <td>
                        {flow.rtt_ms ? (
                          <span
                            className={cn(
                              "font-bold",
                              flow.rtt_ms > 200 ? "text-warn" : "text-ok"
                            )}
                          >
                            {Math.round(flow.rtt_ms)} ms
                          </span>
                        ) : (
                          <span className="text-ink-3">-</span>
                        )}
                      </td>
                      <td>
                        {flow.retransmissions > 0 ? (
                          <span className="font-bold text-warn inline-flex items-center gap-1">
                            <AlertTriangle size={12} />
                            {flow.retransmissions}
                          </span>
                        ) : (
                          <span className="text-ink-3">0</span>
                        )}
                      </td>
                      <td>
                        <Chip
                          tone={
                            isReset ? "flag" : isHalfOpen ? "warn" : "ok"
                          }
                        >
                          {flow.state}
                        </Chip>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
