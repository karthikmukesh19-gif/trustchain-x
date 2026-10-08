export function Brand({ tone = "dark" }: { tone?: "dark" | "light" }) {
  const text = tone === "dark" ? "text-white" : "text-ink";
  return (
    <div className="flex items-center gap-2.5">
      <svg viewBox="0 0 32 32" className="h-7 w-7 shrink-0" aria-hidden>
        <rect width="32" height="32" rx="7" fill="#12161c" stroke="#2a313c" />
        <path
          d="M9 11.5h6.2M12.1 11.5v10M17.5 13.2l5.6 7.6M23.1 13.2l-5.6 7.6"
          stroke="#5eead4"
          strokeWidth="2.4"
          strokeLinecap="round"
          fill="none"
        />
      </svg>
      <span className={`font-mono text-[15px] font-semibold tracking-tight ${text}`}>
        TrustChain<span className="text-signal">-X</span>
      </span>
    </div>
  );
}
