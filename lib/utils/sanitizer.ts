/**
 * Sanitization utility to ensure zero-risk handling of packet payloads and network telemetry.
 * Prevents XSS, script injection, and crashes from malformed binary payloads.
 */

/**
 * Escapes HTML characters in strings before rendering
 */
export function escapeHtml(unsafe: string): string {
  if (!unsafe) return "";
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Converts a Uint8Array or byte array into a safe printable ASCII representation.
 * Any non-printable byte (< 32 or > 126) is converted to a harmless dot ('.')
 */
export function bytesToSafeAscii(bytes: Uint8Array | number[]): string {
  let ascii = "";
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte >= 32 && byte <= 126) {
      ascii += String.fromCharCode(byte);
    } else {
      ascii += ".";
    }
  }
  return ascii;
}

/**
 * Formats bytes into standard hex dump representation (16 bytes per line)
 */
export function bytesToHexDump(bytes: Uint8Array | number[], maxBytes: number = 256): string[] {
  const lines: string[] = [];
  const limit = Math.min(bytes.length, maxBytes);
  
  for (let offset = 0; offset < limit; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, Math.min(offset + 16, limit)));
    const offsetHex = offset.toString(16).padStart(4, "0").toUpperCase();
    
    const hexParts = chunk.map(b => b.toString(16).padStart(2, "0").toUpperCase());
    const hexPadded = hexParts.join(" ").padEnd(48, " ");
    
    const ascii = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
    
    lines.push(`${offsetHex}  ${hexPadded}  |${ascii}|`);
  }
  
  if (bytes.length > maxBytes) {
    lines.push(`... [Truncated ${bytes.length - maxBytes} additional bytes for safe preview]`);
  }
  
  return lines;
}

/**
 * Sanitizes arbitrary text payload or string to prevent embedded code execution
 */
export function sanitizePayloadString(input: string, maxLength: number = 500): string {
  if (!input) return "";
  // Strip null bytes and non-printable characters
  const clean = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ".");
  return clean.slice(0, maxLength);
}
