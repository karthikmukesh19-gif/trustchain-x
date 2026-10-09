import { FiDatabase } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { CountChart } from "../charts/PlatformCharts";
import { JobPanel } from "../components/analysis/JobPanel";
import { NotAnalysed, ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { Confidence, Meaning, NotRun, Panel, Score, percent, useLayer, words } from "../components/platform/common";
import { StatTile } from "../components/StatTile";
import { Badge } from "../components/StatusBadge";
import { getDatasetQuality, listDatasets, startDatasetValidation } from "../services/platform";
import { formatDateTime, shortSha } from "../utils/format";
import type { DatasetList, DatasetQuality, DatasetStatus } from "../utils/platformTypes";
import type { JobType } from "../utils/types";

const JOB_TYPES: JobType[] = ["dataset_validation"];
const STATUS_TONE: Record<DatasetStatus, "good" | "warn" | "bad" | "neutral"> = { VALID: "good", WARNING: "warn", LOW_CONFIDENCE: "warn", INVALID: "bad", UNKNOWN: "neutral" };
const CLASS_COLOURS = { true: "#b3261e", false: "#0f766e" };

export function DatasetStatusBadge({ status }: { status: DatasetStatus }) {
  return <Badge tone={STATUS_TONE[status] ?? "neutral"}>{status.replace("_", " ")}</Badge>;
}

export function DatasetPage() {
  const { id: projectId = "" } = useParams();
  const { data, jobs } = useLayer<{ list: DatasetList; quality: DatasetQuality | null }>(projectId, JOB_TYPES, async () => {
    const list = await listDatasets(projectId);
    return { list, quality: list.current ? await getDatasetQuality(projectId, list.current.id) : null };
  });
  const list = data.data?.list;
  const result = data.data?.quality ?? null;
  const quality = result?.quality ?? null;
  const current = list?.current ?? null;
  const start = <button type="button" className="btn btn-primary" disabled={jobs.busy || jobs.starting} onClick={() => void jobs.run(() => startDatasetValidation(projectId))}>
    <FiDatabase aria-hidden /> {current ? "Validate again" : "Build and validate"}</button>;

  return (
    <ProjectPageShell projectId={projectId}>
      {data.loading && !list ? <Spinner label="Loading dataset" /> : data.error && !list ? <ErrorNotice message={data.error} onRetry={() => void data.reload()} />
        : !list?.snapshot ? <NotAnalysed projectId={projectId} /> : (
          <div className="space-y-6">
            <JobPanel title="Dataset validation" jobs={jobs} actions={start} testId="dataset-job"
              idle="Builds a dataset from the stored analysis results (one record per dependency, each field traceable to its source), hashes every record with SHA-256, and checks integrity, completeness, consistency, duplicates and balance."
              failureNote="The validation did not finish. Any result shown is from an earlier run." />
            <Meaning testId="dataset-limitation">{list.limitation}</Meaning>
            {!current || !quality || !result ? (
              <NotRun title="Analysis not available">No dataset has been built for commit {shortSha(list.snapshot.commit_sha)}. Until one is validated its quality is unknown.</NotRun>
            ) : (
              <>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5" data-testid="dataset-summary">
                  <StatTile label="Validation status" value={<DatasetStatusBadge status={quality.status} />} note={quality.reasons[0]} />
                  <StatTile label="Quality score" value={<Score value={quality.quality_score} />} note="0–100, every factor shown below" />
                  <StatTile label="Confidence" value={<Confidence value={quality.confidence} />} note={`${quality.records} record(s)`} />
                  <StatTile label="Duplicates" value={quality.duplicates.exact_duplicate_records + quality.duplicates.repeated_identity_records} note={`${quality.duplicates.near_duplicate_records} near-duplicate record(s)`} />
                  <StatTile label="Suspicious records" value={quality.suspicious_records.length} note={`${quality.duplicates.label_conflict_records} with conflicting labels`} />
                </div>

                <Panel title="Quality factors" testId="quality-factors">
                  <table className="w-full text-left text-sm">
                    <thead className="eyebrow border-b border-line"><tr><th className="py-2 pr-3">Factor</th><th className="pr-3">Weight</th><th className="pr-3">Value</th><th className="pr-3">Points</th><th>Detail</th></tr></thead>
                    <tbody>
                      {quality.factors.map((factor) => (
                        <tr key={factor.name} className="border-b border-line/60 align-top" data-testid="quality-factor" data-factor={factor.name} data-status={factor.status}>
                          <td className="py-2 pr-3 font-medium">{words(factor.name)}</td><td className="pr-3 font-mono">{factor.weight}</td>
                          <td className="pr-3 font-mono">{factor.value === null ? "unknown" : percent(factor.value)}</td><td className="pr-3 font-mono">{factor.contribution ?? "—"}</td>
                          <td className="text-[13px] text-ink-soft">{factor.detail}{factor.warnings.map((warning) => <div key={warning} className="text-warn">{warning}</div>)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Panel>

                <div className="grid gap-6 lg:grid-cols-2">
                  <Panel title="Provenance" testId="provenance">
                    <p className="text-sm">{percent(quality.provenance.field_provenance_completeness)} of known fields are traceable to a source; {quality.provenance.source_diversity} analysis layer(s) contributed.</p>
                    <ul className="mt-2 space-y-1 text-[13px]">
                      {quality.provenance.sources.map((source) => <li key={source.layer}><span className="font-medium">{words(source.layer)}</span> <span className="font-mono text-xs text-muted">{source.collection} · {source.basis.toLowerCase()}{source.model_version ? ` · ${source.model_version}` : ""}</span></li>)}
                    </ul>
                    {quality.provenance.source_layers_missing.length > 0 && <p className="mt-2 text-sm text-warn" data-testid="provenance-missing">No data from: {quality.provenance.source_layers_missing.map(words).join(", ")}.</p>}
                  </Panel>
                  <Panel title="Integrity" testId="integrity">
                    <p className="text-sm">Checked just now: <Badge tone={result.integrity_now.status === "VERIFIED" ? "good" : result.integrity_now.status === "MISMATCH" ? "bad" : "neutral"}>{result.integrity_now.status.replace("_", " ")}</Badge>
                      {result.integrity_now.records_checked !== undefined ? ` ${result.integrity_now.records_checked} record hash(es) recomputed.` : ` ${result.integrity_now.reason ?? ""}`}</p>
                    {result.integrity_now.altered_records && result.integrity_now.altered_records.length > 0 && <p className="mt-1 text-sm text-danger">Altered since they were written: {result.integrity_now.altered_records.join(", ")}</p>}
                    <dl className="mt-2 space-y-1 font-mono text-[11px] text-muted">
                      <div><dt className="inline">dataset hash ({result.dataset.hash_algorithm}): </dt><dd className="inline break-all">{result.dataset.dataset_hash}</dd></div>
                      <div><dt className="inline">chain hash: </dt><dd className="inline break-all">{result.dataset.chain_hash}</dd></div>
                    </dl>
                    <p className="mt-2 text-xs text-muted">Version chain {list.chain_intact ? "intact" : list.chain_intact === false ? "BROKEN: an earlier version is missing or altered" : "not established"}.</p>
                  </Panel>
                  <Panel title="Class distribution" testId="class-distribution">
                    {quality.balance.labelled > 0 ? <CountChart counts={{ true: quality.balance.classes.true, false: quality.balance.classes.false }} label="Records labelled vulnerable and not vulnerable" testId="class-chart" colours={CLASS_COLOURS} />
                      : <p className="text-sm text-muted">The label is unknown for every record.</p>}
                    <p className="mt-1 text-xs text-muted">Label “{quality.balance.label}”: {quality.balance.classes.true} true, {quality.balance.classes.false} false, {quality.balance.unlabelled} unknown.{quality.balance.note ? ` ${quality.balance.note}` : ""}</p>
                  </Panel>
                  <Panel title="Missing data" testId="missing-data">
                    <p className="text-sm">{quality.completeness.filled} of {quality.completeness.cells} cells hold a value ({percent(quality.completeness.value)}).</p>
                    {Object.keys(quality.completeness.missing_by_field).length === 0 ? <p className="mt-1 text-sm text-muted">No field is missing in any record.</p> : (
                      <ul className="mt-2 space-y-0.5 font-mono text-xs">{Object.entries(quality.completeness.missing_by_field).map(([field, count]) => <li key={field}>{words(field)}: missing in {count} record(s)</li>)}</ul>
                    )}
                  </Panel>
                </div>

                <Panel title="Suspicious records" testId="suspicious-records">
                  {quality.suspicious_records.length === 0 ? <p className="text-sm text-muted">No record breaks the schema or contradicts itself.</p> : (
                    <ul className="space-y-2 text-sm">{quality.suspicious_records.map((record) => (
                      <li key={record.record_id}><span className="font-mono text-xs font-semibold">{record.record_id}</span>
                        <ul className="ml-4 list-disc text-[13px]">{record.problems.map((problem) => <li key={problem.rule}>{problem.detail}</li>)}</ul></li>
                    ))}</ul>
                  )}
                  <p className="mt-2 text-xs text-muted">{quality.duplicates.note}</p>
                </Panel>

                <Panel title="Validation history" testId="validation-history">
                  <table className="w-full text-left text-sm">
                    <thead className="eyebrow border-b border-line"><tr><th className="py-2 pr-3">Validated</th><th className="pr-3">Status</th><th className="pr-3">Score</th><th className="pr-3">Confidence</th><th>Records</th></tr></thead>
                    <tbody>{result.history.map((row, index) => (
                      <tr key={index} className="border-b border-line/60" data-testid="validation-row"><td className="py-1.5 pr-3">{formatDateTime(row.created_at)}</td><td className="pr-3"><DatasetStatusBadge status={row.status} /></td>
                        <td className="pr-3"><Score value={row.quality_score} /></td><td className="pr-3"><Confidence value={row.confidence} /></td><td className="font-mono">{row.records}</td></tr>
                    ))}</tbody>
                  </table>
                  <h3 className="mt-4 text-sm font-semibold">Versions</h3>
                  <ul className="mt-1 space-y-1 text-[13px]" data-testid="dataset-versions">
                    {list.items.map((version) => (
                      <li key={version.id}>Version {version.version} · {version.record_count} record(s) · commit {shortSha(version.commit_sha)} · {formatDateTime(version.created_at)}
                        {version.changes?.comparable ? ` · ${version.changes.added} added, ${version.changes.removed} removed, ${version.changes.changed} changed` : ""}
                        {version.records_pruned ? " · records no longer kept (hashes are)" : ""}</li>
                    ))}
                  </ul>
                </Panel>
              </>
            )}
          </div>
        )}
    </ProjectPageShell>
  );
}
