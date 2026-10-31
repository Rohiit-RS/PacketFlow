"use client";

import { useState } from "react";
import { Finding } from "@/lib/engine/types";
import { FindingCard } from "./FindingCard";
import { Button, Chip, Panel, SectionTitle, Swatch, cn } from "./ui";
import { ShieldCheck, ShieldAlert, Wrench, Flame } from "lucide-react";

interface FindingsListProps {
  findings: Finding[];
  onSelectEvidence?: (packetSummary: string) => void;
}

type FilterType = "ALL" | "ATTACK" | "FAULT" | "CRITICAL";

export function FindingsList({ findings, onSelectEvidence }: FindingsListProps) {
  const [filter, setFilter] = useState<FilterType>("ALL");

  const attacksCount = findings.filter(f => f.category === "ATTACK").length;
  const faultsCount = findings.filter(f => f.category === "FAULT").length;
  const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;

  const filteredFindings = findings.filter(f => {
    if (filter === "ATTACK") return f.category === "ATTACK";
    if (filter === "FAULT") return f.category === "FAULT";
    if (filter === "CRITICAL") return f.severity === "CRITICAL";
    return true;
  });

  return (
    <div id="findings-section" className="space-y-4 scroll-mt-20">
      <SectionTitle
        sub="Differentiated cyber attacks and operational outages with confidence ratings and dual remediation"
        action={
          <div className="flex items-center gap-1 p-1 bg-sunk rounded-full border border-rule text-xs">
            <button
              type="button"
              onClick={() => setFilter("ALL")}
              className={cn(
                "px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer text-xs",
                filter === "ALL" ? "bg-raised text-ink shadow-xs" : "text-ink-2 hover:text-ink"
              )}
            >
              All ({findings.length})
            </button>
            <button
              type="button"
              onClick={() => setFilter("ATTACK")}
              className={cn(
                "px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer flex items-center gap-1.5 text-xs",
                filter === "ATTACK" ? "bg-brand-soft text-brand" : "text-ink-2 hover:text-ink"
              )}
            >
              <Swatch color="var(--color-flag)" />
              Attacks ({attacksCount})
            </button>
            <button
              type="button"
              onClick={() => setFilter("FAULT")}
              className={cn(
                "px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer flex items-center gap-1.5 text-xs",
                filter === "FAULT" ? "bg-brand-soft text-brand" : "text-ink-2 hover:text-ink"
              )}
            >
              <Swatch color="var(--color-warn)" />
              Faults ({faultsCount})
            </button>
            <button
              type="button"
              onClick={() => setFilter("CRITICAL")}
              className={cn(
                "px-3 py-1 rounded-full font-semibold transition-colors cursor-pointer flex items-center gap-1.5 text-xs",
                filter === "CRITICAL" ? "bg-flag text-on-brand shadow-xs" : "text-ink-2 hover:text-flag"
              )}
            >
              <Flame size={12} />
              Critical ({criticalCount})
            </button>
          </div>
        }
      >
        Diagnostic Findings ({findings.length})
      </SectionTitle>

      {findings.length === 0 ? (
        <Panel className="p-12 text-center border-dashed border-rule-strong">
          <div className="h-12 w-12 rounded-full bg-ok-soft text-ok flex items-center justify-center mx-auto mb-3">
            <ShieldCheck size={24} />
          </div>
          <h3 className="text-base font-bold text-ink">Zero Faults or Cyber Incidents Detected</h3>
          <p className="text-sm text-ink-2 max-w-md mx-auto mt-1">
            All packets conform strictly to protocol specifications with normal round-trip latencies, clean DNS lookups, and uncompromised ARP mappings.
          </p>
        </Panel>
      ) : filteredFindings.length === 0 ? (
        <Panel className="p-8 text-center border-dashed border-rule-strong">
          <p className="text-sm text-ink-2">No findings match the selected filter ({filter}).</p>
          <Button variant="secondary" size="sm" onClick={() => setFilter("ALL")} className="mt-2">
            Reset Filters
          </Button>
        </Panel>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              onSelectEvidence={onSelectEvidence}
            />
          ))}
        </div>
      )}
    </div>
  );
}
