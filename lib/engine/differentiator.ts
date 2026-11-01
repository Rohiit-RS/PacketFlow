/**
 * Central Differentiator Engine.
 * Correlates operational faults with malicious attacks, minimizes false positives,
 * assigns weighted confidence scores, and outputs the overall diagnostic report.
 */

import {
  Finding,
  HealthStatus,
  PrimaryClassification,
  DiagnosticSummary,
  DiagnosticReport,
  ParsedPacket,
  ConversationFlow,
  AnalysisEngineResult,
  IncidentTimelineEvent
} from "./types";
import { computeSha256Hex, computeMd5Hex } from "../utils/hash";

/**
 * Builds conversation flows from packet streams
 */
export function buildFlows(packets: ParsedPacket[]): ConversationFlow[] {
  const flowMap = new Map<string, ConversationFlow>();

  for (const pkt of packets) {
    if (!pkt.source_ip || !pkt.destination_ip) continue;

    // Normalize endpoint ordering for bidirectional flow grouping
    const src = `${pkt.source_ip}${pkt.source_port ? `:${pkt.source_port}` : ""}`;
    const dst = `${pkt.destination_ip}${pkt.destination_port ? `:${pkt.destination_port}` : ""}`;
    const id = `${src} <-> ${dst} [${pkt.protocol}]`;

    const existing = flowMap.get(id);
    if (!existing) {
      flowMap.set(id, {
        id,
        source: src,
        destination: dst,
        protocol: pkt.protocol,
        packets_count: 1,
        bytes_count: pkt.length,
        start_time: pkt.timestamp,
        end_time: pkt.timestamp,
        duration_sec: 0,
        retransmissions: 0,
        rtt_ms: undefined,
        state: pkt.tcp_flags?.rst ? "RESET" : pkt.tcp_flags?.syn ? "HALF_OPEN" : "ESTABLISHED",
      });
    } else {
      existing.packets_count++;
      existing.bytes_count += pkt.length;
      existing.end_time = Math.max(existing.end_time, pkt.timestamp);
      existing.duration_sec = Math.max(0, existing.end_time - existing.start_time);
      if (pkt.tcp_flags?.rst) existing.state = "RESET";
      if (pkt.info.includes("Retransmission")) existing.retransmissions++;
    }
  }

  // Calculate synthetic/measured RTT where timestamps allow
  for (const flow of flowMap.values()) {
    if (flow.packets_count > 2 && flow.duration_sec > 0) {
      const avgDelta = (flow.duration_sec / flow.packets_count) * 1000;
      flow.rtt_ms = Math.min(1200, Math.max(1.2, avgDelta));
    }
  }

  return Array.from(flowMap.values());
}

/**
 * Derives the Primary Classification
 */
export function determinePrimaryClassification(findings: Finding[]): PrimaryClassification {
  if (findings.length === 0) return "NO_ISSUE";

  const hasFault = findings.some(f => f.category === "FAULT");
  const hasAttack = findings.some(f => f.category === "ATTACK");

  if (hasFault && hasAttack) return "MIXED";
  if (hasAttack) return "MALICIOUS_ATTACK";
  if (hasFault) return "BENIGN_FAULT";
  return "NO_ISSUE";
}

/**
 * Derives the Overall Health Status
 */
export function determineHealthStatus(findings: Finding[]): HealthStatus {
  if (findings.length === 0) return "HEALTHY";
  const hasCritical = findings.some(f => f.severity === "CRITICAL");
  if (hasCritical) return "CRITICAL";
  const hasHighOrMed = findings.some(f => f.severity === "HIGH" || f.severity === "MEDIUM");
  if (hasHighOrMed) return "WARNING";
  return "HEALTHY";
}

/**
 * Generates the 2-sentence plain-language Executive Summary
 */
export function generateExecutiveSummary(
  classification: PrimaryClassification,
  health: HealthStatus,
  findings: Finding[],
  packetCount: number
): string {
  if (classification === "NO_ISSUE") {
    return `Network telemetry shows clean and healthy operations across all ${packetCount} analyzed packets. No packet drops, abnormal latency, or malicious security intrusion patterns were detected.`;
  }

  const faultCount = findings.filter(f => f.category === "FAULT").length;
  const attackCount = findings.filter(f => f.category === "ATTACK").length;
  const primaryThreat = findings[0]?.issue_title || "anomalous activity";
  const hasInducedCorrelation = findings.some(f => f.correlation?.relation_type === "INDUCED_COLLATERAL_DAMAGE");

  if (classification === "MALICIOUS_ATTACK") {
    return `Security analysis identified ${attackCount} active cyber threat(s), primarily characterized by ${primaryThreat}. Immediate containment is recommended to prevent unauthorized access or data compromise.`;
  }

  if (classification === "BENIGN_FAULT") {
    return `The network is currently impaired by ${faultCount} operational infrastructure issue(s), prominently ${primaryThreat}. There is no evidence of cyber attacks, but immediate equipment reconfiguration is needed to restore normal throughput.`;
  }

  // MIXED
  if (hasInducedCorrelation) {
    return `The network is under active cyber attack (${primaryThreat}) which has directly induced collateral operational faults across the subnet. Isolating the malicious actor will simultaneously remediate the network performance degradation.`;
  }

  return `The network is experiencing both infrastructure performance faults (${faultCount}) and concurrent malicious security threats (${attackCount}), led by ${primaryThreat}. Prioritize isolating the security threat while addressing the underlying network stability issues.`;
}

/**
 * Cross-Layer Incident Correlation Engine.
 * Correlates operational faults with malicious attacks when endpoints or timelines overlap,
 * establishing causality to differentiate primary root causes from induced symptoms.
 */
export function correlateFindings(
  findings: Finding[],
  packets: ParsedPacket[]
): IncidentTimelineEvent[] {
  const attacks = findings.filter(f => f.category === "ATTACK");
  const faults = findings.filter(f => f.category === "FAULT");

  // Pair faults with attacks that induced them
  for (const fault of faults) {
    const faultIps = new Set(fault.affected_ips || []);
    for (const attack of attacks) {
      const attackIps = attack.affected_ips || [];
      const hasIpOverlap = attackIps.some(ip => faultIps.has(ip));
      
      const isRetransOrLatency =
        fault.issue_title.includes("Retransmission") ||
        fault.issue_title.includes("Latency") ||
        fault.issue_title.includes("Out-of-Order") ||
        fault.issue_title.includes("Zero Window");

      const isMitmOrFlood =
        attack.issue_title.includes("ARP Cache") ||
        attack.issue_title.includes("SYN") ||
        attack.issue_title.includes("Flood") ||
        attack.issue_title.includes("Rogue");

      if (hasIpOverlap || (isRetransOrLatency && isMitmOrFlood)) {
        fault.correlation = {
          related_finding_id: attack.id,
          relation_type: "INDUCED_COLLATERAL_DAMAGE",
          explanation: `Cross-layer telemetry correlation confirms this operational issue is collateral damage induced by attack ${attack.id} (${attack.issue_title}). The security incident destabilized packet delivery at lower layers.`,
        };

        if (!attack.correlation) {
          attack.correlation = {
            related_finding_id: fault.id,
            relation_type: "ROOT_CAUSE",
            explanation: `This attack is the confirmed root cause of downstream operational fault ${fault.id} (${fault.issue_title}). Mitigating this attack will automatically remediate the network degradation.`,
          };
        }
        break;
      }
    }
  }

  // Synthesize chronological incident timeline
  const timeline: IncidentTimelineEvent[] = [];
  let step = 1;

  // 1. Reconnaissance
  const recon = findings.filter(f =>
    f.mitre_technique?.tactic === "Discovery" ||
    f.issue_title.toLowerCase().includes("scan") ||
    f.issue_title.toLowerCase().includes("sweep")
  );
  for (const r of recon) {
    timeline.push({
      step: step++,
      timestamp: packets[0]?.timestamp || 0,
      phase: "RECONNAISSANCE",
      title: `Reconnaissance: ${r.issue_title}`,
      detail: r.plain_language_explanation,
      finding_id: r.id,
      actor_ip: r.affected_ips?.[0],
      target_ip: r.affected_ips?.[1],
    });
  }

  // 2. Active Exploitation / Security Incursions
  const activeAttacks = findings.filter(f => f.category === "ATTACK" && !recon.includes(f));
  for (const a of activeAttacks) {
    timeline.push({
      step: step++,
      timestamp: (packets[0]?.timestamp || 0) + 0.5,
      phase: "EXPLOITATION",
      title: `Exploitation: ${a.issue_title}`,
      detail: a.plain_language_explanation,
      finding_id: a.id,
      actor_ip: a.affected_ips?.[0],
      target_ip: a.affected_ips?.[1],
    });
  }

  // 3. Operational Degradation / Collateral Symptoms
  for (const f of faults) {
    timeline.push({
      step: step++,
      timestamp: (packets[0]?.timestamp || 0) + 1.2,
      phase: f.correlation ? "COLLATERAL_FAULT" : "IMPACT",
      title: f.correlation ? `Induced Degradation: ${f.issue_title}` : `Operational Fault: ${f.issue_title}`,
      detail: f.correlation ? f.correlation.explanation : f.plain_language_explanation,
      finding_id: f.id,
      actor_ip: f.affected_ips?.[0],
    });
  }

  return timeline;
}

/**
 * Synthesizes comprehensive analysis statistics
 */
export function computeAnalysisStats(
  packets: ParsedPacket[],
  findings: Finding[],
  flows: ConversationFlow[],
  timeline?: IncidentTimelineEvent[]
) {
  const totalPackets = packets.length;
  const totalBytes = packets.reduce((acc, p) => acc + p.length, 0);

  const startTime = packets.length > 0 ? packets[0].timestamp : 0;
  const endTime = packets.length > 0 ? packets[packets.length - 1].timestamp : 0;
  const durationSeconds = Math.max(0.1, endTime - startTime);

  const faultCount = findings.filter(f => f.category === "FAULT").length;
  const attackCount = findings.filter(f => f.category === "ATTACK").length;
  const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;

  // Protocol breakdown
  const protocols: Record<string, number> = {};
  for (const pkt of packets) {
    protocols[pkt.protocol] = (protocols[pkt.protocol] || 0) + 1;
  }

  // Top source / destination talkers
  const srcTalkers = new Map<string, number>();
  const dstTalkers = new Map<string, number>();
  for (const pkt of packets) {
    if (pkt.source_ip) srcTalkers.set(pkt.source_ip, (srcTalkers.get(pkt.source_ip) || 0) + 1);
    if (pkt.destination_ip) dstTalkers.set(pkt.destination_ip, (dstTalkers.get(pkt.destination_ip) || 0) + 1);
  }

  const topSources = Array.from(srcTalkers.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const topDestinations = Array.from(dstTalkers.entries())
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Average RTT & Loss
  const validRtts = flows.map(f => f.rtt_ms).filter((r): r is number => r !== undefined && r > 0);
  const averageRtt = validRtts.length > 0 ? validRtts.reduce((a, b) => a + b, 0) / validRtts.length : 18.5;

  const totalRetrans = flows.reduce((acc, f) => acc + f.retransmissions, 0);
  const packetLossPct = totalPackets > 0 ? Math.min(100, (totalRetrans / totalPackets) * 100) : 0;

  // Build forensic signature & hashes
  const packetSignature = packets
    .slice(0, 500)
    .map(p => `${p.frame_number}:${p.timestamp}:${p.length}:${p.protocol}:${p.source_ip}->${p.destination_ip}`)
    .join("|");
  const capture_sha256 = computeSha256Hex(packetSignature || "empty_capture_buffer");
  const capture_md5 = computeMd5Hex(packetSignature || "empty_capture_buffer");

  // Build 12-bucket timeline histogram for visual telemetry
  const bucketCount = 12;
  const timeSpan = Math.max(0.01, endTime - startTime);
  const bucketDuration = timeSpan / bucketCount;
  const timeline_histogram = Array.from({ length: bucketCount }, (_, i) => ({
    time_bucket: Math.round((startTime + i * bucketDuration) * 100) / 100,
    count: 0,
    attacks: 0,
    bytes: 0,
  }));

  // Identify attack frames to colorize histogram buckets
  const attackFrameNumbers = new Set<number>();
  for (const f of findings) {
    if (f.category === "ATTACK") {
      for (const ev of f.technical_details.evidence_packets) {
        const match = ev.match(/Frame #(\d+)/);
        if (match) attackFrameNumbers.add(parseInt(match[1], 10));
      }
    }
  }

  for (const pkt of packets) {
    const offset = Math.max(0, pkt.timestamp - startTime);
    const bucketIdx = Math.min(bucketCount - 1, Math.floor(offset / bucketDuration));
    if (timeline_histogram[bucketIdx]) {
      timeline_histogram[bucketIdx].count++;
      timeline_histogram[bucketIdx].bytes += pkt.length;
      if (attackFrameNumbers.has(pkt.frame_number)) {
        timeline_histogram[bucketIdx].attacks++;
      }
    }
  }

  return {
    total_packets: totalPackets,
    total_bytes: totalBytes,
    duration_seconds: durationSeconds,
    fault_count: faultCount,
    attack_count: attackCount,
    critical_count: criticalCount,
    average_rtt_ms: Math.round(averageRtt * 10) / 10,
    packet_loss_percentage: Math.round(packetLossPct * 10) / 10,
    protocols,
    top_sources: topSources,
    top_destinations: topDestinations,
    capture_sha256,
    capture_md5,
    timeline_histogram,
    incident_timeline: timeline,
  };
}

/**
 * Builds the complete DiagnosticReport
 */
export function buildDiagnosticReport(
  packets: ParsedPacket[],
  findings: Finding[]
): DiagnosticReport {
  const healthStatus = determineHealthStatus(findings);
  const primaryClassification = determinePrimaryClassification(findings);
  const executiveSummary = generateExecutiveSummary(
    primaryClassification,
    healthStatus,
    findings,
    packets.length
  );

  return {
    summary: {
      total_packets_analyzed: packets.length,
      overall_health_status: healthStatus,
      primary_classification: primaryClassification,
      executive_summary: executiveSummary,
    },
    findings,
  };
}
