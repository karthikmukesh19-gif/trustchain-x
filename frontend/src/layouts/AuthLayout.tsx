import type { ReactNode } from "react";

import { Brand } from "../components/Brand";

const EVIDENCE_LAYERS = [
  "Dependencies and their graph",
  "SBOM integrity",
  "Known vulnerabilities and reachability",
  "Maintainer and commit behaviour",
];

export function AuthLayout({ title, subtitle, children }: { title: string; subtitle: string; children: ReactNode }) {
  return (
    <div className="grid min-h-screen lg:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
      <aside className="hidden flex-col justify-between bg-ink p-10 text-white lg:flex">
        <Brand />
        <div>
          <p className="eyebrow !text-signal">Software supply chain trust</p>
          <h2 className="mt-3 max-w-md text-3xl font-semibold leading-tight tracking-tight">
            Can this software, and everything it depends on, be trusted?
          </h2>
          <p className="mt-4 max-w-md text-sm leading-relaxed text-white/65">
            TrustChain-X is being built to correlate evidence from several layers of a repository into one
            explainable trust score. Registration and project management are available now; the analysis engine
            is under development.
          </p>
          <ul className="mt-6 space-y-2 font-mono text-[13px] text-white/75">
            {EVIDENCE_LAYERS.map((layer, index) => (
              <li key={layer} className="flex gap-3">
                <span className="text-signal">{String(index + 1).padStart(2, "0")}</span>
                {layer}
              </li>
            ))}
          </ul>
        </div>
        <p className="text-xs text-white/40">Evidence layers planned for the analysis engine.</p>
      </aside>

      <main className="flex items-center justify-center px-4 py-10 sm:px-8">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Brand tone="light" />
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="mt-1 text-sm text-muted">{subtitle}</p>
          <div className="mt-6">{children}</div>
        </div>
      </main>
    </div>
  );
}
