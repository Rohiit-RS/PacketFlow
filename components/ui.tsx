import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { ComponentProps, ReactNode } from "react";

export const cn = (...c: ClassValue[]) => twMerge(clsx(c));

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost" | "inverse" | "outline";
const VARIANT: Record<ButtonVariant, string> = {
  primary: "bg-brand text-on-brand hover:bg-brand-deep shadow-[0_1px_2px_rgb(12_18_34/0.12)] disabled:opacity-50",
  secondary: "bg-raised text-ink border border-rule hover:border-rule-strong hover:bg-sunk disabled:text-ink-3",
  danger: "bg-flag text-on-brand hover:bg-flag-deep disabled:opacity-50",
  ghost: "text-brand hover:bg-brand-soft",
  inverse: "bg-raised text-brand hover:bg-brand-soft",
  outline: "bg-transparent text-ink border border-rule hover:border-rule-strong hover:bg-sunk",
};

export function buttonClass(variant: ButtonVariant = "primary", size: "md" | "sm" | "lg" = "md") {
  return cn(
    "inline-flex items-center justify-center gap-2 rounded-[10px] font-semibold transition-[background-color,border-color,color,transform] duration-150 active:translate-y-px disabled:cursor-not-allowed disabled:active:translate-y-0 select-none cursor-pointer",
    size === "sm" ? "min-h-9 px-3 text-sm" : size === "lg" ? "min-h-12 px-6 text-[1.05rem]" : "min-h-11 px-4 text-[0.97rem]",
    VARIANT[variant]
  );
}

export function Button({
  variant = "primary",
  size = "md",
  className,
  ...p
}: ComponentProps<"button"> & { variant?: ButtonVariant; size?: "md" | "sm" | "lg" }) {
  return <button {...p} className={cn(buttonClass(variant, size), className)} />;
}

export type ChipTone = "pend" | "brand" | "flag" | "ok" | "warn" | "muted";
const TONE: Record<ChipTone, string> = {
  pend: "bg-pend-soft text-pend-ink border-transparent",
  brand: "bg-brand-soft text-brand border-transparent",
  flag: "bg-flag-soft text-flag border-transparent",
  ok: "bg-ok-soft text-ok border-transparent",
  warn: "bg-warn-soft text-warn border-transparent",
  muted: "bg-sunk text-ink-2 border-transparent",
};

/** Status pill. `line` carries state by form as well as hue. */
export function Chip({
  tone = "pend",
  line,
  children,
  className,
}: {
  tone?: ChipTone;
  line?: "pending" | "ended";
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold whitespace-nowrap",
        TONE[tone],
        line === "pending" && "line-pending border-current",
        line === "ended" && "line-ended",
        className
      )}
    >
      {children}
    </span>
  );
}

export function SectionTitle({
  children,
  action,
  id,
  sub,
  className,
}: {
  children: ReactNode;
  action?: ReactNode;
  id?: string;
  sub?: ReactNode;
  className?: string;
}) {
  return (
    <div id={id} className={cn("flex flex-wrap items-end justify-between gap-3 mb-4 scroll-mt-24", className)}>
      <div>
        <h2 className="text-lg font-bold tracking-[-0.02em] text-ink">{children}</h2>
        {sub && <p className="text-sm text-ink-2 mt-0.5">{sub}</p>}
      </div>
      {action}
    </div>
  );
}

export function Panel({
  children,
  className,
  ...p
}: ComponentProps<"section">) {
  return (
    <section
      {...p}
      className={cn("border border-rule rounded-2xl bg-raised transition-colors", className)}
    >
      {children}
    </section>
  );
}

/** Swatch code square */
export function Swatch({
  color,
  title,
  className,
}: {
  color: string;
  title?: string;
  className?: string;
}) {
  return (
    <span
      className={cn("swatch", className)}
      style={{ backgroundColor: color }}
      title={title}
    />
  );
}
