import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis,
} from "recharts";

import type { ScoreBucket, TrustComponent, TrustPoint } from "../utils/platformTypes";

const INK = "#12161c";
const TRUST = "#0f766e";
const WARN = "#a35a00";
const DANGER = "#b3261e";
const MUTED = "#8d93a0";
const GRID = "#e8e5dc";
const TICK = { fontSize: 11, fill: "#646b78" };
const LEVEL_COLOUR: Record<string, string> = { HIGH: DANGER, CRITICAL: DANGER, MEDIUM: WARN, LOW: MUTED, UNKNOWN: MUTED, INFO: MUTED };
const day = (value: string) => new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });

function Frame({ label, height = 220, children, testId }: { label: string; height?: number; children: React.ReactElement; testId: string }) {
  return (
    <div role="img" aria-label={label} style={{ height }} data-testid={testId}>
      <ResponsiveContainer width="100%" height="100%">{children}</ResponsiveContainer>
    </div>
  );
}

/** Trust and risk over time. Points without a score (insufficient data) leave a gap: a line is never drawn through them. */
export function TrustTrendChart({ points }: { points: TrustPoint[] }) {
  const data = points.map((point) => ({ at: point.created_at, Trust: point.trust_score, Risk: point.risk_score }));
  return (
    <Frame label="Trust and risk score over time" testId="trust-trend-chart">
      <LineChart data={data} margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="at" tickFormatter={day} tick={TICK} />
        <YAxis domain={[0, 100]} tick={TICK} />
        <Tooltip labelFormatter={(value) => new Date(String(value)).toLocaleString()} />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Line type="monotone" dataKey="Trust" stroke={TRUST} strokeWidth={2} dot connectNulls={false} isAnimationActive={false} />
        <Line type="monotone" dataKey="Risk" stroke={DANGER} strokeWidth={2} dot connectNulls={false} isAnimationActive={false} />
      </LineChart>
    </Frame>
  );
}

/** Points of the risk score each known component accounts for. Unknown components are listed beside the chart, not drawn as zero. */
export function ContributionChart({ components }: { components: Pick<TrustComponent, "label" | "contribution" | "status" | "risk">[] }) {
  const data = components.filter((component) => component.status === "KNOWN").map((component) => ({ name: component.label, Contribution: component.contribution ?? 0, risk: component.risk }));
  return (
    <Frame label="Contribution of each component to the risk score" height={Math.max(180, data.length * 30 + 40)} testId="contribution-chart">
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, left: 40, bottom: 0 }}>
        <CartesianGrid stroke={GRID} horizontal={false} />
        <XAxis type="number" tick={TICK} />
        <YAxis type="category" dataKey="name" width={150} tick={TICK} />
        <Tooltip formatter={(value, _name, item) => [`${String(value)} points (component risk ${String((item.payload as { risk: number }).risk)})`, "Contribution"]} />
        <Bar dataKey="Contribution" fill={INK} isAnimationActive={false} />
      </BarChart>
    </Frame>
  );
}

/** Counts per category (severity, status, level). */
export function CountChart({ counts, label, testId, colours }: { counts: Record<string, number>; label: string; testId: string; colours?: Record<string, string> }) {
  const data = Object.entries(counts).map(([name, count]) => ({ name: name.replace(/_/g, " ").toLowerCase(), key: name, count }));
  return (
    <Frame label={label} height={200} testId={testId}>
      <BarChart data={data} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="name" tick={TICK} interval={0} />
        <YAxis allowDecimals={false} tick={TICK} />
        <Tooltip />
        <Bar dataKey="count" isAnimationActive={false}>
          {data.map((entry) => <Cell key={entry.key} fill={(colours ?? LEVEL_COLOUR)[entry.key] ?? INK} />)}
        </Bar>
      </BarChart>
    </Frame>
  );
}

/** How many items fall in each fifth of a 0-100 score. */
export function DistributionChart({ buckets, label, testId }: { buckets: ScoreBucket[]; label: string; testId: string }) {
  return (
    <Frame label={label} height={200} testId={testId}>
      <BarChart data={buckets} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="range" tick={TICK} />
        <YAxis allowDecimals={false} tick={TICK} />
        <Tooltip />
        <Bar dataKey="count" fill={INK} isAnimationActive={false} />
      </BarChart>
    </Frame>
  );
}

/** Anomaly score of each analysed commit over time. */
export function CommitTimelineChart({ commits }: { commits: { commit_sha: string; committed_at: string | null; anomaly_score: number; level: string }[] }) {
  const data = commits.filter((commit) => commit.committed_at).map((commit) => ({ at: new Date(commit.committed_at as string).getTime(), score: commit.anomaly_score, level: commit.level, sha: commit.commit_sha.slice(0, 10) }));
  return (
    <Frame label="Anomaly score of each analysed commit over time" testId="commit-timeline-chart">
      <ScatterChart margin={{ top: 8, right: 12, left: -18, bottom: 0 }}>
        <CartesianGrid stroke={GRID} />
        <XAxis type="number" dataKey="at" domain={["dataMin", "dataMax"]} tickFormatter={(value) => day(new Date(Number(value)).toISOString())} tick={TICK} />
        <YAxis type="number" dataKey="score" domain={[0, 100]} tick={TICK} name="Anomaly" />
        <ZAxis range={[50, 50]} />
        <Tooltip content={({ payload }) => {
          const item = payload?.[0]?.payload as { sha: string; score: number; at: number; level: string } | undefined;
          return item ? <div className="rounded border border-line bg-surface px-2 py-1 text-xs"><div className="font-mono">{item.sha}</div><div>anomaly {item.score} ({item.level.toLowerCase()})</div><div className="text-muted">{new Date(item.at).toLocaleString()}</div></div> : null;
        }} />
        <Scatter data={data} isAnimationActive={false}>
          {data.map((entry) => <Cell key={entry.sha} fill={LEVEL_COLOUR[entry.level] ?? INK} />)}
        </Scatter>
      </ScatterChart>
    </Frame>
  );
}

/** Commits per week. */
export function ActivityChart({ weeks }: { weeks: { week_start: string; commits: number; contributors: number }[] }) {
  return (
    <Frame label="Commits per week" testId="activity-chart">
      <BarChart data={weeks} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="week_start" tickFormatter={day} tick={TICK} minTickGap={24} />
        <YAxis allowDecimals={false} tick={TICK} />
        <Tooltip labelFormatter={(value) => `Week of ${day(String(value))}`} />
        <Bar dataKey="commits" name="Commits" fill={INK} isAnimationActive={false} />
      </BarChart>
    </Frame>
  );
}
