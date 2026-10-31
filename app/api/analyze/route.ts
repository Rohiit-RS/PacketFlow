import { NextRequest, NextResponse } from "next/server";
import { DiagnosticEngine } from "@/lib/engine/diagnosticEngine";

export const dynamic = "force-dynamic";

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
