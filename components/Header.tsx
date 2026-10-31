"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Layers,
  ShieldAlert,
  ArrowDownUp,
  FileJson,
  BookOpen,
  Download,
  Sparkles,
  Network,
  Wrench,
  FileText,
} from "lucide-react";
import { Wordmark } from "./shell/Logo";
import { ThemeToggle } from "./shell/ThemeToggle";
import { Button, Chip, Swatch, cn } from "./ui";
import { useCapture } from "@/lib/context/CaptureContext";
import { toast } from "sonner";

export function Header() {
  const pathname = usePathname();
  const { analysisResult, currentCaptureName } = useCapture();

  const findingsCount = analysisResult.report.findings.length;
  const packetsCount = analysisResult.packets.length;
  const flowsCount = analysisResult.flows.length;

  const downloadReportJson = () => {
    try {
      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(analysisResult.report, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `packetflow-diagnostic-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      toast.success("Diagnostic report JSON downloaded!");
    } catch {
      toast.error("Failed to generate download.");
    }
  };

  const navLinks = [
    { href: "/", label: "Overview", icon: Layers, badge: null },
    { href: "/findings", label: "Findings", icon: ShieldAlert, badge: findingsCount },
    { href: "/packets", label: "Packets", icon: Layers, badge: packetsCount },
    { href: "/flows", label: "Flows", icon: ArrowDownUp, badge: flowsCount },
    { href: "/topology", label: "Topology", icon: Network, badge: null },
    { href: "/remediation", label: "Remediation", icon: Wrench, badge: null },
    { href: "/report", label: "Report", icon: FileText, badge: null },
    { href: "/schema", label: "JSON", icon: FileJson, badge: null },
    { href: "/docs", label: "Docs", icon: BookOpen, badge: null },
  ];

  return (
    <header className="bg-raised border-b border-rule sticky top-0 z-40 backdrop-blur-md bg-raised/95">
      <div className="mx-auto max-w-[1360px] px-4 sm:px-8 h-16 flex items-center justify-between gap-4">
        {/* Left: Brand Wordmark */}
        <Link href="/" className="rounded-[10px] focus-visible:outline-none">
          <Wordmark />
        </Link>

        {/* Center: Desktop Navigation Tabs (Pill style) */}
        <nav className="hidden lg:flex items-center gap-1 p-1 bg-sunk/80 rounded-full border border-rule">
          {navLinks.map((item) => {
            const isActive =
              item.href === "/"
                ? pathname === "/"
                : pathname === item.href || pathname.startsWith(`${item.href}/`);
            const Icon = item.icon;

            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "inline-flex items-center gap-1.5 px-3.5 h-9 rounded-full text-sm font-medium transition-colors whitespace-nowrap",
                  isActive
                    ? "bg-brand text-on-brand shadow-xs font-semibold"
                    : "text-ink-2 hover:text-ink hover:bg-raised"
                )}
              >
                <Icon size={14} />
                <span>{item.label}</span>
                {item.badge !== null && (
                  <span
                    className={cn(
                      "px-1.5 py-0.2 rounded-full text-xs font-mono",
                      isActive
                        ? "bg-brand-deep text-on-brand font-bold"
                        : "bg-raised text-ink-2 border border-rule-soft"
                    )}
                  >
                    {item.badge}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Right: Actions & ThemeToggle */}
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={downloadReportJson}
            title="Download strict schema JSON"
            className="hidden sm:inline-flex"
          >
            <Download size={14} className="text-ink-2" />
            <span>Export JSON</span>
          </Button>

          <div className="h-5 w-px bg-rule mx-1 hidden sm:block" />

          <ThemeToggle />
        </div>
      </div>

      {/* Mobile/Tablet Sub-Navigation Scrolling Bar */}
      <div className="lg:hidden border-t border-rule-soft px-4 py-2 overflow-x-auto flex items-center gap-1.5 bg-raised/90">
        {navLinks.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname === item.href || pathname.startsWith(`${item.href}/`);

          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "inline-flex items-center gap-1.5 px-3 h-7 rounded-full text-xs font-semibold transition-colors shrink-0",
                isActive
                  ? "bg-brand text-on-brand"
                  : "bg-sunk text-ink-2 hover:text-ink"
              )}
            >
              <span>{item.label}</span>
              {item.badge !== null && (
                <span className="text-[10px] font-mono opacity-80">({item.badge})</span>
              )}
            </Link>
          );
        })}
      </div>
    </header>
  );
}
