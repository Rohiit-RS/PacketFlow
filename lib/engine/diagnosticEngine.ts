/**
 * Automated Network Packet Analysis & Security Diagnostic Engine.
 * Central diagnostic engine coordinating safe packet parsing, fault detection,
 * attack detection, differentiation, and strict JSON output generation.
 */

import { ParsedPacket, AnalysisEngineResult, DiagnosticReport } from "./types";
import { parsePcapBuffer, parseTelemetryJson } from "./pcapParser";
import { detectNetworkFaults } from "./faultDetector";
import { detectSecurityAttacks } from "./attackDetector";
import {
  buildFlows,
  buildDiagnosticReport,
  computeAnalysisStats
} from "./differentiator";

export class DiagnosticEngine {
  /**
   * Analyzes an array of pre-parsed packets or telemetry items.
   */
  public static analyzePackets(packets: ParsedPacket[]): AnalysisEngineResult {
    if (!packets || packets.length === 0) {
      const emptyReport: DiagnosticReport = {
        summary: {
          total_packets_analyzed: 0,
          overall_health_status: "HEALTHY",
          primary_classification: "NO_ISSUE",
          executive_summary: "No network packet telemetry was provided for analysis.",
        },
        findings: [],
      };

      return {
        report: emptyReport,
        packets: [],
        flows: [],
        stats: {
          total_packets: 0,
          total_bytes: 0,
          duration_seconds: 0,
          fault_count: 0,
          attack_count: 0,
          critical_count: 0,
          average_rtt_ms: 0,
          packet_loss_percentage: 0,
          protocols: {},
          top_sources: [],
          top_destinations: [],
        },
      };
    }

    // Step 1: Build conversation flows
    const flows = buildFlows(packets);

    // Step 2: Detect operational network faults
    const faults = detectNetworkFaults(packets, flows, 1);

    // Step 3: Detect malicious security attacks
    const attacks = detectSecurityAttacks(packets, flows, faults.length + 1);

    // Combine all findings
    const allFindings = [...attacks, ...faults];

    // Step 4: Differentiate, score, and build strict JSON diagnostic report
    const report = buildDiagnosticReport(packets, allFindings);

    // Step 5: Compute auxiliary telemetry stats for the UI
    const stats = computeAnalysisStats(packets, allFindings, flows);

    return {
      report,
      packets,
      flows,
      stats,
    };
  }

  /**
   * Ingests and analyzes binary PCAP or PCAPNG buffer.
   */
  public static analyzePcapBuffer(buffer: ArrayBuffer | Uint8Array, maxPackets = 5000): AnalysisEngineResult {
    const packets = parsePcapBuffer(buffer, maxPackets);
    return this.analyzePackets(packets);
  }

  /**
   * Ingests and analyzes JSON packet telemetry string.
   */
  public static analyzeJsonTelemetry(jsonString: string): AnalysisEngineResult {
    const packets = parseTelemetryJson(jsonString);
    return this.analyzePackets(packets);
  }
}
