/**
 * Formatting helpers for telemetry and display
 */

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function formatDuration(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(2)}s`;
  const mins = Math.floor(seconds / 60);
  const remainingSecs = (seconds % 60).toFixed(1);
  return `${mins}m ${remainingSecs}s`;
}

export const COMMON_PORTS: Record<number, string> = {
  20: "FTP-Data",
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  67: "DHCP-Server",
  68: "DHCP-Client",
  69: "TFTP",
  80: "HTTP",
  110: "POP3",
  123: "NTP",
  135: "RPC",
  137: "NetBIOS",
  138: "NetBIOS",
  139: "NetBIOS",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  587: "SMTP-Sub",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  6379: "Redis",
  8080: "HTTP-Proxy",
  8443: "HTTPS-Alt",
};

export function getPortServiceName(port?: number): string {
  if (!port) return "";
  return COMMON_PORTS[port] ? `${port} (${COMMON_PORTS[port]})` : `${port}`;
}
