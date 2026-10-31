"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";
import { cn } from "../ui";

type Mode = "light" | "dark";

const read = (): Mode =>
  typeof document !== "undefined" && document.documentElement.dataset.theme === "dark"
    ? "dark"
    : "light";

export function ThemeToggle({ className }: { className?: string }) {
  const [mode, setMode] = useState<Mode>("light");

  useEffect(() => {
    setMode(read());
  }, []);

  const flip = () => {
    const next: Mode = read() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("packetflow-theme", next);
    } catch {}
    setMode(next);
  };

  return (
    <button
      type="button"
      onClick={flip}
      aria-label={mode === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      title={mode === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      className={cn(
        "inline-flex h-9 w-9 items-center justify-center rounded-xl border border-rule text-ink-2 hover:bg-sunk hover:text-ink transition-colors cursor-pointer",
        className
      )}
    >
      {mode === "dark" ? <Sun size={17} strokeWidth={2} /> : <Moon size={17} strokeWidth={2} />}
    </button>
  );
}

export const THEME_SCRIPT = `(function(){try{var s=localStorage.getItem('packetflow-theme');var m=window.matchMedia('(prefers-color-scheme: dark)');var a=function(){var t=localStorage.getItem('packetflow-theme')||(m.matches?'dark':'light');document.documentElement.dataset.theme=t;};a();if(!s&&m.addEventListener)m.addEventListener('change',function(){if(!localStorage.getItem('packetflow-theme'))a();});}catch(e){document.documentElement.dataset.theme='light';}})();`;
