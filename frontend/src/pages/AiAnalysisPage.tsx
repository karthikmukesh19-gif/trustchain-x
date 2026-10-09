import { useState } from "react";
import { FiCpu } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { BasisTag, Confidence, LevelBadge, Meaning, NotRun, percent, useLayer, words } from "../components/platform/common";
import { StatTile } from "../components/StatTile";
import { useAsync } from "../hooks/useAsync";
import { getAiFinding, listAiFindings, startAiAnalysis } from "../services/platform";
import type { AiFinding, AiList, EvidenceItem, FindingStatement } from "../utils/platformTypes";
import type { JobType } from "../utils/types";

const JOB_TYPES: JobType[] = ["ai_security_analysis"];

function Statement({ statement, evidence }: { statement: FindingStatement; evidence: Map<string, EvidenceItem> }) {
  return (
    <li className="flex items-start gap-2 text-sm" data-testid="finding-statement" data-basis={statement.basis}>
      <BasisTag basis={statement.basis} />
      <span>
        {statement.text}{" "}
        {statement.evidence_refs.map((ref) => (
          <span key={ref} className="font-mono text-[11px] text-trust" title={evidence.get(ref)?.summary ?? ref}>[{ref}]</span>
        ))}
      </span>
    </li>
  );
}

function Reasoning({ projectId, findingId }: { projectId: string; findingId: string }) {
  const { data, error, loading } = useAsync(() => getAiFinding(projectId, findingId), [projectId, findingId]);
  if (loading) return <Spinner label="Loading reasoning" />;
  if (error) return <ErrorNotice message={error} />;
  if (!data?.conditions) return null;
  const detail = data.confidence_detail;
  return (
    <div className="mt-3" data-testid="finding-reasoning">
      <h4 className="eyebrow">Conditions the rule evaluated</h4>
      <ul className="mt-1 space-y-0.5 font-mono text-xs">
        {data.conditions.map((condition) => (
          <li key={condition.condition} data-result={condition.result}>
            {condition.result === "TRUE" ? "held" : condition.result === "FALSE" ? "did not hold" : "unknown"} — {words(condition.condition)}{condition.note ? ` (${condition.note})` : ""}
          </li>
        ))}
      </ul>
      {detail && <p className="mt-2 text-xs text-muted">Confidence = weakest cited evidence {detail.weakest_evidence} × corroboration {detail.corroboration} ({detail.layers} layer(s)) × completeness {detail.completeness}.</p>}
    </div>
  );
}

function Finding({ projectId, finding }: { projectId: string; finding: AiFinding }) {
  const [open, setOpen] = useState(false);
  const evidence = new Map(finding.evidence.map((item) => [item.ref, item]));
  const subject = finding.subject.package_name ? `${finding.subject.package_name}${finding.subject.advisory ? ` · ${finding.subject.advisory}` : ""}` : null;
  return (
    <li className="card p-4" data-testid="ai-finding" data-category={finding.category} data-severity={finding.severity}>
      <div className="flex flex-wrap items-center gap-2">
        <LevelBadge level={finding.severity} />
        <h3 className="font-mono text-[13px] font-semibold">{finding.category}</h3>
        {subject && <span className="text-sm text-muted">{subject}</span>}
        <span className="ml-auto text-xs text-muted">confidence <Confidence value={finding.confidence} /></span>
      </div>
      <p className="mt-1 text-xs text-muted">{finding.category_meaning}</p>
      <ul className="mt-3 space-y-1.5">{finding.statements.map((statement, index) => <Statement key={index} statement={statement} evidence={evidence} />)}</ul>
      <div className="mt-3 rounded-md bg-paper px-3 py-2"><ul><Statement statement={finding.recommendation} evidence={evidence} /></ul></div>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-muted">
        <span>Contributing layers:</span>
        {finding.contributing_layers.map((layer) => <span key={layer} className="rounded border border-line px-1.5 py-0.5 font-mono" data-testid="finding-layer">{words(layer)}</span>)}
        <button type="button" className="ml-auto font-medium text-trust hover:underline" onClick={() => setOpen(!open)} aria-expanded={open}>{open ? "Hide evidence and reasoning" : "Evidence and reasoning"}</button>
      </div>
      {open && (
        <div className="mt-3 border-t border-line pt-3">
          <h4 className="eyebrow">Evidence cited</h4>
          <ul className="mt-1 space-y-1 text-[13px]" data-testid="finding-evidence">
            {finding.evidence.map((item) => (
              <li key={item.ref} className="flex items-start gap-2">
                <span className="font-mono text-[11px] text-trust">[{item.ref}]</span> <BasisTag basis={item.basis} />
                <span>{item.summary} <span className="font-mono text-[11px] text-muted">{item.collection}/{String(item.record_id).slice(0, 12)}</span></span>
              </li>
            ))}
          </ul>
          <Reasoning projectId={projectId} findingId={finding.finding_id} />
        </div>
      )}
    </li>
  );
}

export function AiAnalysisPage() {
  const { id: projectId = "" } = useParams();
  const { data, jobs } = useLayer<AiList>(projectId, JOB_TYPES, () => listAiFindings(projectId));
  const [severity, setSeverity] = useState("");
  const list = data.data;
  const summary = list?.analysis?.summary;
  const order = list?.severities ?? [];
  const items = (list?.items ?? []).filter((item) => !severity || order.indexOf(item.severity) >= order.indexOf(severity as AiFinding["severity"]));
  const start = <button type="button" className="btn btn-primary" disabled={jobs.busy || jobs.starting} onClick={() => void jobs.run(() => startAiAnalysis(projectId))}>
    <FiCpu aria-hidden /> {list?.analysis ? "Run again" : "Start analysis"}</button>;

  return (
    <ProjectPageShell projectId={projectId}>
      {data.loading && !list ? <Spinner label="Loading findings" /> : data.error && !list ? <ErrorNotice message={data.error} onRetry={() => void data.reload()} />
        : !list?.snapshot ? <NotAnalysed projectId={projectId} /> : (
          <div className="space-y-6">
            <JobPanel title="Cross-layer security reasoning" jobs={jobs} actions={start} testId="ai-job"
              idle="Correlates what the other layers stored into findings, using fixed rules. Every statement cites the stored records it rests on; a finding that cites nothing is rejected before it is saved."
              failureNote="The reasoning run did not finish. Findings shown are from an earlier run." />
            <Meaning testId="ai-meaning">{list.meaning}</Meaning>
            {!list.analysis || !summary ? (
              <NotRun title="Analysis not available">No reasoning run exists for this snapshot. Run the other analyses first: the more layers have results, the more can be correlated.</NotRun>
            ) : (
              <>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" data-testid="ai-summary">
                  <StatTile label="Findings" value={summary.findings} note={`${(summary.by_severity.CRITICAL ?? 0) + (summary.by_severity.HIGH ?? 0)} high or critical`} />
                  <StatTile label="Evidence grounding" value={percent(summary.grounding.evidence_grounding)} note={`of ${summary.grounding.statements} statement(s) cite stored evidence (measured)`} />
                  <StatTile label="Unsupported-claim rate" value={percent(summary.grounding.unsupported_claim_rate)} note={`${summary.grounding.findings_rejected} finding(s) rejected as ungrounded`} />
                  <StatTile label="Evidence items" value={summary.evidence_items} note={`provider: ${summary.provider}${summary.deterministic ? " (rules only, no model)" : ""}`} />
                </div>
                {summary.layers_missing.length > 0 && (
                  <p className="text-sm text-warn" data-testid="ai-missing-layers">Not analysed, so not considered: {summary.layers_missing.map(words).join(", ")}. What those layers would show is unknown.</p>
                )}
                <div className="flex items-center justify-between gap-3">
                  <h2 className="text-base font-semibold">Findings</h2>
                  <select aria-label="Minimum severity" className="rounded-md border border-line bg-surface px-2 py-1 text-sm" value={severity} onChange={(event) => setSeverity(event.target.value)}>
                    <option value="">All severities</option>
                    {order.filter((value) => value !== "INFO").map((value) => <option key={value} value={value}>{value} and above</option>)}
                  </select>
                </div>
                {items.length === 0 ? <p className="text-sm text-muted">{list.items.length === 0 ? "The rules produced no finding from the stored results." : "No finding at this severity."}</p>
                  : <ul className="space-y-3" data-testid="ai-findings">{items.map((finding) => <Finding key={finding.finding_id} projectId={projectId} finding={finding} />)}</ul>}
              </>
            )}
          </div>
        )}
    </ProjectPageShell>
  );
}
