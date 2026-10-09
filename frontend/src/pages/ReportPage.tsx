import { useState } from "react";
import { FiDownload, FiPrinter } from "react-icons/fi";
import { useParams } from "react-router-dom";

import { ProjectPageShell } from "../components/analysis/ProjectPageShell";
import { ErrorNotice, Spinner } from "../components/Feedback";
import { BasisTag, Meaning } from "../components/platform/common";
import { useAsync } from "../hooks/useAsync";
import { downloadReportMarkdown, getReport } from "../services/platform";
import { errorMessage } from "../utils/errors";
import { formatDateTime } from "../utils/format";
import type { Report, ReportSection } from "../utils/platformTypes";

function Refs({ refs }: { refs: string[] }) {
  return <span className="font-mono text-[11px] text-trust" data-testid="report-refs">{refs.map((ref) => `[${ref}]`).join(" ")}</span>;
}

function Section({ section }: { section: ReportSection }) {
  return (
    <section className="card p-5" id={`section-${section.id}`} data-testid="report-section" data-section={section.id} data-available={section.available}>
      <h2 className="text-base font-semibold">{section.number}. {section.title}</h2>
      <ul className="mt-3 space-y-2">
        {section.statements.map((statement, index) => (
          <li key={index} className="flex items-start gap-2 text-sm" data-testid="report-statement">
            <BasisTag basis={statement.basis} /> <span>{statement.text} <Refs refs={statement.evidence} /></span>
          </li>
        ))}
      </ul>
      {section.tables.map((table) => (
        <div key={table.title} className="mt-4 overflow-x-auto">
          <h3 className="text-sm font-semibold">{table.title}</h3>
          <table className="mt-1 w-full text-left text-[13px]">
            <thead className="eyebrow border-b border-line"><tr>{table.columns.map((column) => <th key={column} className="py-1.5 pr-3">{column}</th>)}<th>Evidence</th></tr></thead>
            <tbody>
              {table.rows.map((row, index) => (
                <tr key={index} className="border-b border-line/60 align-top">
                  {row.cells.map((cell, position) => <td key={position} className="py-1.5 pr-3">{cell === null ? "—" : String(cell)}</td>)}
                  <td><Refs refs={row.evidence} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </section>
  );
}

export function ReportPage() {
  const { id: projectId = "" } = useParams();
  const { data: report, error, loading, reload } = useAsync<Report>(() => getReport(projectId), [projectId]);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  async function download() {
    try {
      setDownloadError(null);
      const blob = await downloadReportMarkdown(projectId);
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `trustchain-x-report-${projectId}.md`;
      link.click();
      URL.revokeObjectURL(link.href);
    } catch (caught) {
      setDownloadError(errorMessage(caught));
    }
  }

  const actions = (
    <>
      <button type="button" className="btn btn-secondary" onClick={() => window.print()}><FiPrinter aria-hidden /> Print</button>
      <button type="button" className="btn btn-primary" onClick={() => void download()} disabled={!report}><FiDownload aria-hidden /> Download Markdown</button>
    </>
  );

  return (
    <ProjectPageShell projectId={projectId} actions={actions}>
      {loading && !report ? <Spinner label="Building report" /> : error && !report ? <ErrorNotice message={error} onRetry={() => void reload()} /> : report && (
        <div className="space-y-5" data-testid="report">
          {downloadError && <ErrorNotice message={downloadError} />}
          <div>
            <h2 className="text-xl font-semibold tracking-tight">{report.title}</h2>
            <p className="mt-1 text-sm text-muted">
              Generated {formatDateTime(report.generated_at)} from stored results · commit {report.snapshot?.commit_sha ?? "not analysed"} · {report.statement_count} statements, {report.evidence.length} evidence references
            </p>
          </div>
          <Meaning testId="report-meaning">
            Every statement is labelled by how it is known and followed by the references it rests on; section 15 lists what each reference points to. A section whose layer has not been analysed says so and reports nothing.
          </Meaning>
          <nav aria-label="Report sections" className="flex flex-wrap gap-x-4 gap-y-1 text-[13px]">
            {report.sections.map((section) => <a key={section.id} className="text-trust hover:underline" href={`#section-${section.id}`}>{section.number}. {section.title}</a>)}
          </nav>
          {report.sections.map((section) => (
            <div key={section.id}>
              <Section section={section} />
              {section.id === "evidence" && (
                <div className="card mt-3 overflow-x-auto p-5" data-testid="evidence-index">
                  <h3 className="text-sm font-semibold">Evidence index</h3>
                  <table className="mt-1 w-full text-left text-[12px]">
                    <thead className="eyebrow border-b border-line"><tr><th className="py-1.5 pr-3">Ref</th><th className="pr-3">Kind</th><th className="pr-3">Layer</th><th className="pr-3">Source</th><th className="pr-3">Identifier</th><th>As of</th></tr></thead>
                    <tbody>
                      {report.evidence.map((item) => (
                        <tr key={item.ref} className="border-b border-line/60">
                          <td className="py-1 pr-3 font-mono text-trust">{item.ref}</td><td className="pr-3">{item.kind}</td><td className="pr-3">{item.layer}</td>
                          <td className="pr-3 font-mono">{item.kind === "record" ? item.collection : item.document}</td>
                          <td className="pr-3 font-mono">{item.kind === "record" ? item.record_id : item.model_version ?? "—"}</td><td>{item.as_of ? formatDateTime(item.as_of) : "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </ProjectPageShell>
  );
}
