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
      </head>
      <body className="min-h-full flex flex-col antialiased bg-canvas text-ink">
        <CaptureProvider>
          <Header />
          <div className="flex-1 flex flex-col">{children}</div>
          <footer className="border-t border-rule bg-raised mt-16 py-6 text-xs text-ink-3 print:hidden no-print">
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
