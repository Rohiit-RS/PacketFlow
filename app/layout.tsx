import type { Metadata, Viewport } from "next";
import { Hanken_Grotesk } from "next/font/google";
import { Toaster } from "sonner";
import { THEME_SCRIPT } from "@/components/shell/ThemeToggle";
import { CaptureProvider } from "@/lib/context/CaptureContext";
import { Header } from "@/components/Header";
import "./globals.css";

const grotesk = Hanken_Grotesk({
  variable: "--font-grotesk",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "PacketFlow: Automated Network Packet Analysis & Security Diagnostic Engine",
  description:
    "Central diagnostic engine that analyzes technical network telemetry, differentiates outages from security incidents, and outputs structured diagnoses with clear remediation steps.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#0a0e17" },
  ],
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${grotesk.variable} h-full antialiased`}
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <style
          dangerouslySetInnerHTML={{
            __html: `
              @media print {
                @page {
                  margin: 0;
                  size: auto;
                }
                header,
                footer,
                nav,
                aside,
                .no-print,
                [data-no-print],
                .print\\:hidden {
                  display: none !important;
                  visibility: hidden !important;
                  height: 0 !important;
                  width: 0 !important;
                  overflow: hidden !important;
                  position: absolute !important;
                  top: -9999px !important;
                  left: -9999px !important;
                  opacity: 0 !important;
                  pointer-events: none !important;
                }
                body {
                  background: #ffffff !important;
                  color: #0f172a !important;
                  margin: 0 !important;
                  padding: 1.2cm !important;
                }
                * {
                  position: static !important;
                  box-shadow: none !important;
                  backdrop-filter: none !important;
                  -webkit-backdrop-filter: none !important;
                  -webkit-print-color-adjust: exact !important;
                  print-color-adjust: exact !important;
                }
                /* Never slice cards, boxes, or tables across page boundaries */
                .break-inside-avoid,
                .print-box,
                div[class*="rounded-"],
                div[class*="border"],
                table,
                tr,
                tbody {
                  break-inside: avoid !important;
                  page-break-inside: avoid !important;
                }
                h1, h2, h3, h4, h5, h6 {
                  break-after: avoid !important;
                  page-break-after: avoid !important;
                }
                .h-full,
                div[class*="items-stretch"] > * {
                  height: auto !important;
                  min-height: 0 !important;
                }
              }
            `,
          }}
        />
      </head>
      <body className="min-h-full flex flex-col antialiased bg-canvas text-ink">
        <CaptureProvider>
          <Header />
          <div className="flex-1 flex flex-col">{children}</div>
          <footer
            id="site-footer"
            data-no-print="true"
            className="border-t border-rule bg-raised mt-16 py-6 text-xs text-ink-3 print:hidden no-print"
          >
            <div className="mx-auto max-w-[1360px] px-4 sm:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="font-bold text-ink">PacketFlow</span>
                <span>&bull;</span>
                <span>Automated Network Diagnostic Engine</span>
              </div>
              <div>IIITDM Kancheepuram &bull; Network Diagnostics Platform</div>
            </div>
          </footer>
        </CaptureProvider>
        <Toaster
          position="top-center"
          richColors
          closeButton
          toastOptions={{
            style: {
              fontFamily: "var(--font-sans)",
              fontSize: "15px",
              borderRadius: "12px",
            },
          }}
        />
      </body>
    </html>
  );
}
