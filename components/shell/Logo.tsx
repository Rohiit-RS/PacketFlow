/**
 * PacketFlow mark: three network flow bursts in their protocol/threat code colours,
 * staggered in time on a shared axis, read as one coherent capture stream.
 */
export function Mark({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" aria-hidden="true" className="shrink-0">
      <rect x="2" y="4" width="16" height="5" rx="2.5" fill="var(--color-c-exploit)" />
      <rect x="8" y="11.5" width="18" height="5" rx="2.5" fill="var(--color-c-routing)" />
      <rect x="4" y="19" width="14" height="5" rx="2.5" fill="var(--color-c-tcp)" />
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="inline-flex items-center gap-2.5">
      <Mark size={28} />
      <span className="flex flex-col">
        <span className="text-[1.2rem] font-bold tracking-[-0.03em] text-ink leading-tight">
          PacketFlow
        </span>
        <span className="text-[10px] text-ink-3 font-medium tracking-normal hidden sm:inline">
          Automated Network Diagnostics
        </span>
      </span>
    </span>
  );
}
