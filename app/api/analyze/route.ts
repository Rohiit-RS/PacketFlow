import { NextRequest, NextResponse } from "next/server";
import { DiagnosticEngine } from "@/lib/engine/diagnosticEngine";

export const dynamic = "force-dynamic";

/**
 * GET Handler for /api/analyze.
 * When visited in a browser (Accept: text/html), renders an interactive API Explorer & Playground.
 * When requested programmatically, returns JSON endpoint specifications and sample usage.
 */
export async function GET(req: NextRequest) {
  const accept = req.headers.get("accept") || "";

  // If opened directly in a browser, return an interactive HTML API Explorer page
  if (accept.includes("text/html")) {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PacketFlow &bull; REST API Explorer (/api/analyze)</title>
  <style>
    :root {
      --bg: #f4f6fa;
      --surface: #ffffff;
      --border: #dce1ea;
      --text: #0c1222;
      --text-muted: #5f697d;
      --brand: #1f4fff;
      --brand-soft: #e9eeff;
      --ok: #0a7f46;
      --ok-soft: #e3f6ec;
      --flag: #d0174f;
      --code-bg: #0f172a;
      --code-text: #e2e8f0;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0b0f19;
        --surface: #111827;
        --border: #1f293d;
        --text: #f1f5f9;
        --text-muted: #94a3b8;
        --brand: #3b82f6;
        --brand-soft: rgba(59, 130, 246, 0.15);
        --ok: #22c55e;
        --ok-soft: rgba(34, 197, 94, 0.15);
        --flag: #f43f5e;
        --code-bg: #020617;
        --code-text: #f8fafc;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2.5rem 1rem;
    }
    .container { max-width: 1120px; margin: 0 auto; }
    .header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 1.5rem;
      padding-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.35rem 0.8rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 700;
      font-family: monospace;
      background: var(--ok-soft);
      color: var(--ok);
      border: 1px solid var(--ok);
    }
    .title { font-size: 1.85rem; font-weight: 800; letter-spacing: -0.02em; }
    .subtitle { color: var(--text-muted); font-size: 0.95rem; margin-top: 0.25rem; }
    .nav-links { display: flex; gap: 0.85rem; align-items: center; }
    .nav-links a {
      color: var(--brand);
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 600;
    }
    .nav-links a:hover { text-decoration: underline; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 1rem;
      padding: 1.75rem;
      margin-bottom: 1.75rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .card-title {
      font-size: 1.15rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .grid { display: grid; grid-template-columns: 1fr; gap: 1.5rem; }
    @media (min-width: 800px) {
      .grid { grid-template-columns: 1fr 1fr; }
    }
    textarea {
      width: 100%;
      height: 240px;
      background: var(--code-bg);
      color: var(--code-text);
      font-family: monospace;
      font-size: 0.85rem;
      padding: 1rem;
      border-radius: 0.75rem;
      border: 1px solid var(--border);
      resize: vertical;
      line-height: 1.5;
    }
    pre {
      background: var(--code-bg);
      color: var(--code-text);
      font-family: monospace;
      font-size: 0.82rem;
      padding: 1rem;
      border-radius: 0.75rem;
      overflow-x: auto;
      height: 240px;
      border: 1px solid var(--border);
      line-height: 1.5;
    }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.65rem 1.25rem;
      background: var(--brand);
      color: #ffffff;
      border: none;
      border-radius: 0.5rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .btn:hover { opacity: 0.9; }
    .btn-secondary {
      background: var(--surface);
      color: var(--text);
      border: 1px solid var(--border);
    }
    .endpoint-pill {
      font-family: monospace;
      background: var(--brand-soft);
      color: var(--brand);
      padding: 0.2rem 0.5rem;
      border-radius: 0.4rem;
      font-weight: bold;
    }
    .status-ok { color: var(--ok); font-weight: bold; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <div class="badge">&#9679; ENDPOINT ONLINE (HTTP 200)</div>
        <h1 class="title" style="margin-top: 0.5rem;">PacketFlow REST API Explorer</h1>
        <p class="subtitle">Diagnostic endpoint: <span class="endpoint-pill">POST /api/analyze</span></p>
      </div>
      <div class="nav-links">
        <a href="/">&larr; Return to Dashboard</a>
        <span>&bull;</span>
        <a href="/schema">JSON Schema</a>
        <span>&bull;</span>
        <a href="/docs">Technical Manual</a>
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        <span>Interactive API Console (Live Test Runner)</span>
        <span class="subtitle">Direct browser test</span>
      </div>
      <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 1rem;">
        Edit the sample ARP Cache Poisoning attack telemetry below, then click <strong>"Execute Diagnostic POST"</strong> to test the live diagnostic engine:
      </p>

      <div class="grid">
        <div>
          <label style="font-size: 0.8rem; font-weight: bold; text-transform: uppercase; display: block; margin-bottom: 0.5rem;">
            Request Payload (application/json):
          </label>
          <textarea id="requestPayload">[
  {
    "frame_number": 1,
    "timestamp": 1730419200.0,
    "length": 60,
    "protocol": "ARP",
    "arp_opcode": "REPLY",
    "arp_sender_ip": "192.168.1.1",
    "arp_sender_mac": "00:0c:29:8a:4f:1b",
    "info": "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]"
  },
  {
    "frame_number": 2,
    "timestamp": 1730419200.05,
    "length": 60,
    "protocol": "ARP",
    "arp_opcode": "REPLY",
    "arp_sender_ip": "192.168.1.1",
    "arp_sender_mac": "00:0c:29:8a:4f:1b",
    "info": "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]"
  },
  {
    "frame_number": 3,
    "timestamp": 1730419200.1,
    "length": 60,
    "protocol": "ARP",
    "arp_opcode": "REPLY",
    "arp_sender_ip": "192.168.1.1",
    "arp_sender_mac": "00:0c:29:8a:4f:1b",
    "info": "192.168.1.1 is at 00:0c:29:8a:4f:1b [Unsolicited Spoofed Reply]"
  }
]</textarea>
          <div style="margin-top: 0.75rem; display: flex; gap: 0.75rem;">
            <button class="btn" id="runBtn" onclick="runAnalysis()">Execute Diagnostic POST</button>
            <button class="btn btn-secondary" onclick="copyCurl()">Copy cURL</button>
          </div>
        </div>

        <div>
          <label style="font-size: 0.8rem; font-weight: bold; text-transform: uppercase; display: block; margin-bottom: 0.5rem;">
            Engine Response (<span id="responseStatus" class="status-ok">Awaiting Execution</span>):
          </label>
          <pre id="responseJson">// Click "Execute Diagnostic POST" to run live analysis through this endpoint.</pre>
        </div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3 style="font-size: 1.05rem; font-weight: bold; margin-bottom: 0.5rem;">Accepted Input Formats</h3>
        <ul style="font-size: 0.88rem; padding-left: 1.25rem; color: var(--text-muted);">
          <li style="margin-bottom: 0.5rem;"><strong>multipart/form-data:</strong> File upload with <code>file</code> field containing <code>.pcap</code>, <code>.pcapng</code>, or <code>.json</code>.</li>
          <li style="margin-bottom: 0.5rem;"><strong>application/json:</strong> Array of parsed packet telemetry objects or <code>{ packets: [...] }</code>.</li>
          <li style="margin-bottom: 0.5rem;"><strong>application/octet-stream:</strong> Raw binary PCAP byte stream.</li>
        </ul>
      </div>

      <div class="card">
        <h3 style="font-size: 1.05rem; font-weight: bold; margin-bottom: 0.5rem;">Output Schema Compliance</h3>
        <p style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 0.75rem;">
          Outputs strict JSON format featuring <code>summary</code> (classification, health, 2-sentence executive summary) and <code>findings[]</code> (technical details, root cause, and remediation).
        </p>
        <a href="/schema" class="btn btn-secondary" style="font-size: 0.8rem; text-decoration: none;">View Complete JSON Schema &rarr;</a>
      </div>
    </div>
  </div>

  <script>
    async function runAnalysis() {
      const btn = document.getElementById('runBtn');
      const statusEl = document.getElementById('responseStatus');
      const jsonEl = document.getElementById('responseJson');
      
      btn.innerText = 'Analyzing...';
      statusEl.innerText = 'Processing...';
      statusEl.className = '';

      try {
        const payload = document.getElementById('requestPayload').value;
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload
        });

        const data = await res.json();
        statusEl.innerText = 'HTTP ' + res.status + ' OK';
        statusEl.className = 'status-ok';
        jsonEl.innerText = JSON.stringify(data, null, 2);
      } catch (err) {
        statusEl.innerText = 'Error: ' + err.message;
        statusEl.style.color = 'var(--flag)';
        jsonEl.innerText = String(err);
      } finally {
        btn.innerText = 'Execute Diagnostic POST';
      }
    }

    function copyCurl() {
      const curl = "curl -X POST " + window.location.origin + "/api/analyze \\\n  -H 'Content-Type: application/json' \\\n  -d '" + document.getElementById('requestPayload').value.replace(/\\n/g, '').replace(/\\s+/g, ' ') + "'";
      navigator.clipboard.writeText(curl);
      alert('cURL command copied to clipboard!');
    }

    // Auto-run on load so user immediately sees results!
    window.addEventListener('DOMContentLoaded', runAnalysis);
  </script>
</body>
</html>`;

    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache",
      },
    });
  }

  // Programmatic GET response (JSON)
  return NextResponse.json({
    status: "ONLINE",
    engine: "PacketFlow Automated Network Diagnostic Engine v2.4",
    endpoint: "/api/analyze",
    supported_methods: ["GET", "POST"],
    accepted_content_types: [
      "multipart/form-data",
      "application/json",
      "application/octet-stream",
    ],
    message:
      "Send a POST request with packet telemetry or PCAP binary to execute automated diagnosis.",
    sample_usage: {
      curl: "curl -X POST http://localhost:3000/api/analyze -H 'Content-Type: application/json' -d '[{\"frame_number\":1,\"timestamp\":1730419200,\"length\":60,\"protocol\":\"ARP\",\"arp_opcode\":\"REPLY\",\"arp_sender_ip\":\"192.168.1.1\",\"arp_sender_mac\":\"00:0c:29:8a:4f:1b\",\"info\":\"192.168.1.1 is at 00:0c:29:8a:4f:1b\"}]'",
    },
    schema_contract_url: "/schema",
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
