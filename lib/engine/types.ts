/**
 * Types definition for the Automated Network Packet Analysis & Security Diagnostic Engine.
 * Strictly adheres to the evaluation schema and hackathon criteria.
 */

export type HealthStatus = "CRITICAL" | "WARNING" | "HEALTHY";

export type PrimaryClassification = 
  | "BENIGN_FAULT" 
  | "MALICIOUS_ATTACK" 
  | "MIXED" 
  | "NO_ISSUE";

export type FindingCategory = "FAULT" | "ATTACK";

export type SeverityLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface FindingTechnicalDetails {
  root_cause: string;
  evidence_packets: string[];
}

export interface RecommendedRemediation {
  immediate_action: string;
  long_term_fix: string;
}

export interface Finding {
  id: string; // e.g., "FINDING-001"
  category: FindingCategory;
  issue_title: string;
  severity: SeverityLevel;
  confidence_score: number; // 0-100
  plain_language_explanation: string;
  technical_details: FindingTechnicalDetails;
  recommended_remediation: RecommendedRemediation;
}

export interface DiagnosticSummary {
  total_packets_analyzed: number;
  overall_health_status: HealthStatus;
  primary_classification: PrimaryClassification;
  executive_summary: string;
}

/** Strict schema matching the required diagnostic response specification */
export interface DiagnosticReport {
  summary: DiagnosticSummary;
  findings: Finding[];
}

/** Internal parsed packet representation for analysis and deep inspection */
export interface ParsedPacket {
  frame_number: number;
  timestamp: number; // seconds or epoch
  timestamp_iso?: string;
  length: number;
  source_mac?: string;
  destination_mac?: string;
  ether_type?: string;
  source_ip?: string;
  destination_ip?: string;
  ip_version?: 4 | 6;
  protocol: "TCP" | "UDP" | "ICMP" | "ARP" | "DNS" | "DHCP" | "OTHER";
  source_port?: number;
  destination_port?: number;
  info: string;
  
  // TCP specific
  tcp_flags?: {
    syn?: boolean;
    ack?: boolean;
    rst?: boolean;
    fin?: boolean;
    psh?: boolean;
    urg?: boolean;
  };
  tcp_seq?: number;
  tcp_ack?: number;
  tcp_window_size?: number;
  
  // DNS specific
  dns_query?: string;
  dns_qtype?: string;
  dns_response_code?: number;
  dns_answers?: string[];
  
  // ARP specific
  arp_opcode?: "REQUEST" | "REPLY";
  arp_sender_mac?: string;
  arp_sender_ip?: string;
  arp_target_mac?: string;
  arp_target_ip?: string;
  
  // ICMP specific
  icmp_type?: number;
  icmp_code?: number;
  icmp_description?: string;
  
  // DHCP specific
  dhcp_msg_type?: "DISCOVER" | "OFFER" | "REQUEST" | "ACK" | "NAK" | "DECLINE" | "RELEASE";
  dhcp_offered_ip?: string;
  dhcp_server_id?: string;
  
  // Payload
  payload_preview?: string;
  payload_hex?: string;
  payload_size?: number;
}

/** Conversation flow summary */
export interface ConversationFlow {
  id: string;
  source: string;
  destination: string;
  protocol: string;
  packets_count: number;
  bytes_count: number;
  start_time: number;
  end_time: number;
  duration_sec: number;
  retransmissions: number;
  rtt_ms?: number;
  state: "ESTABLISHED" | "RESET" | "HALF_OPEN" | "SCANNING" | "CLOSED";
}

/** Comprehensive engine execution result */
export interface AnalysisEngineResult {
  report: DiagnosticReport;
  packets: ParsedPacket[];
  flows: ConversationFlow[];
  stats: {
    total_packets: number;
    total_bytes: number;
    duration_seconds: number;
    fault_count: number;
    attack_count: number;
    critical_count: number;
    average_rtt_ms: number;
    packet_loss_percentage: number;
    protocols: Record<string, number>;
    top_sources: { ip: string; count: number }[];
    top_destinations: { ip: string; count: number }[];
  };
}
