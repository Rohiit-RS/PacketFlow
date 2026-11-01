import { NextRequest, NextResponse } from "next/server";
import { DiagnosticEngine } from "@/lib/engine/diagnosticEngine";

export const dynamic = "force-dynamic";

/**
 * GET Handler for /api/analyse.
 * When visited in a browser (Accept: text/html), redirects seamlessly to the interactive Next.js API Explorer page (/api).
 * When requested programmatically (curl, Python, Postman), returns JSON endpoint specifications and sample usage.
 */
export async function GET(req: NextRequest) {
  const accept = req.headers.get("accept") || "";

  // If opened directly in a browser, redirect to the full Next.js UI explorer page
  if (accept.includes("text/html")) {
    return NextResponse.redirect(new URL("/api", req.url));
  }

  // Programmatic GET response (JSON)
  return NextResponse.json({
    status: "ONLINE",
    engine: "PacketFlow Automated Network Diagnostic Engine v2.4",
    endpoint: "/api/analyse",
    supported_methods: ["GET", "POST"],
    accepted_content_types: [
      "multipart/form-data",
      "application/json",
      "application/octet-stream",
    ],
    message:
      "Send a POST request with packet telemetry or PCAP binary to execute automated diagnosis.",
    sample_usage: {
      curl: "curl -X POST http://localhost:3000/api/analyse -H 'Content-Type: application/json' -d '[{\"frame_number\":1,\"timestamp\":1730419200,\"length\":60,\"protocol\":\"ARP\",\"arp_opcode\":\"REPLY\",\"arp_sender_ip\":\"192.168.1.1\",\"arp_sender_mac\":\"00:0c:29:8a:4f:1b\",\"info\":\"192.168.1.1 is at 00:0c:29:8a:4f:1b\"}]'",
    },
    schema_contract_url: "/api",
  });
}

/**
 * API route for automated packet capture diagnostic analysis.
 * Accepts binary PCAP/PCAPNG, multipart/form-data, or raw JSON telemetry.
 * Returns strict schema-compliant diagnostic output.
 */
export async function POST(req: NextRequest) {
  try {
    const contentType = req.headers.get("content-type") || "";
    const searchParams = req.nextUrl.searchParams;
    const includeDetails = searchParams.get("include_details") === "true";

    // Case 1: multipart/form-data (File upload)
    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      if (!file) {
        return NextResponse.json({ error: "No file provided in form data." }, { status: 400 });
      }

      const buffer = await file.arrayBuffer();
      const fileName = file.name.toLowerCase();

      let result;
      if (fileName.endsWith(".json")) {
        const text = new TextDecoder().decode(buffer);
        result = DiagnosticEngine.analyzeJsonTelemetry(text);
      } else {
        result = DiagnosticEngine.analyzePcapBuffer(buffer);
      }

      return NextResponse.json(includeDetails ? result : result.report);
    }

    // Case 2: application/json
    if (contentType.includes("application/json")) {
      const body = await req.json();
      const packetsJson = Array.isArray(body) ? JSON.stringify(body) : JSON.stringify(body.packets || []);
      const result = DiagnosticEngine.analyzeJsonTelemetry(packetsJson);
      return NextResponse.json(includeDetails ? result : result.report);
    }

    // Case 3: Raw octet-stream (Direct PCAP binary payload)
    const arrayBuffer = await req.arrayBuffer();
    if (arrayBuffer.byteLength > 0) {
      const result = DiagnosticEngine.analyzePcapBuffer(arrayBuffer);
      return NextResponse.json(includeDetails ? result : result.report);
    }

    return NextResponse.json(
      { error: "Unsupported or empty request body. Provide a .pcap file or JSON packet telemetry." },
      { status: 400 }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : "Internal analysis engine failure";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
