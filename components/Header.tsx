"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Download } from "lucide-react";
import { Wordmark } from "./shell/Logo";
import { ThemeToggle } from "./shell/ThemeToggle";
import { Button, cn } from "./ui";
import { useCapture } from "@/lib/context/CaptureContext";
import { toast } from "sonner";

export function Header() {
  const pathname = usePathname();
  const { analysisResult } = useCapture();

  const findingsCount = analysisResult.report.findings.length;

  const downloadReportJson = () => {
    try {
      const dataStr =
        "data:text/json;charset=utf-8," +
        encodeURIComponent(JSON.stringify(analysisResult.report, null, 2));
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
    { href: "/", label: "Overview" },
    { href: "/findings", label: "Findings", badge: findingsCount > 0 ? findingsCount : null },
    { href: "/packets", label: "Packets" },
    { href: "/flows", label: "Flows" },
    { href: "/topology", label: "Topology" },
    { href: "/remediation", label: "Remediation" },
    { href: "/report", label: "Report" },
    { href: "/api", label: "API" },
    { href: "/docs", label: "Docs" },
  ];

  return (
    <header className="bg-raised/90 backdrop-blur-md border-b border-rule sticky top-0 z-40 print:hidden no-print">
      <div className="mx-auto max-w-[1360px] px-4 sm:px-8 h-16 flex items-center justify-between gap-6">
        {/* Left: Brand Wordmark */}
        <Link href="/" className="shrink-0 rounded-[10px] focus-visible:outline-none">
          <Wordmark />
        </Link>

        {/* Center: Clean, Uncongested Desktop Navigation */}
        <nav aria-label="Main" className="hidden lg:flex items-center gap-1 xl:gap-1.5 flex-1 justify-center max-w-[720px]">
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
                  "inline-flex items-center h-8 px-3 rounded-full text-sm font-medium transition-colors whitespace-nowrap",
                  isActive
                    ? "bg-brand-soft text-brand font-semibold shadow-2xs"
                    : "text-ink-2 hover:text-ink hover:bg-sunk"
                )}
              >
                <span>{item.label}</span>
                {item.badge !== null && (
                  <span
                    className={cn(
                      "ml-1.5 px-1.5 py-0.2 rounded-full text-xs font-mono font-bold leading-none",
                      isActive
                        ? "bg-brand text-on-brand"
                        : "bg-flag-soft text-flag"
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
        <div className="flex items-center gap-2 shrink-0">
          <Button
            variant="secondary"
            size="sm"
            onClick={downloadReportJson}
            title="Download strict schema JSON"
            className="hidden xl:inline-flex h-8 px-3 text-xs"
          >
            <Download size={13} className="text-ink-2" />
            <span>Export JSON</span>
          </Button>

          <div className="h-4 w-px bg-rule mx-1 hidden xl:block" />

          <ThemeToggle />
        </div>
      </div>

      {/* Mobile/Tablet Clean Scrolling Sub-Navigation */}
      <div className="lg:hidden border-t border-rule-soft px-4 py-2 overflow-x-auto flex items-center gap-1.5 bg-raised/95 scrollbar-none">
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
                "inline-flex items-center gap-1 px-3 h-7 rounded-full text-xs font-semibold transition-colors shrink-0 whitespace-nowrap",
                isActive
                  ? "bg-brand-soft text-brand"
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
