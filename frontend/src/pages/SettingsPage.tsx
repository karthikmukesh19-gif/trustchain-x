import { FiRefreshCw } from "react-icons/fi";

import { ErrorNotice, PageHeader, Spinner } from "../components/Feedback";
import { Badge } from "../components/StatusBadge";
import { useAuth } from "../context/AuthContext";
import { useAsync } from "../hooks/useAsync";
import { getLiveness, getReadiness } from "../services/health";
import { formatDate, formatDateTime } from "../utils/format";

function Row({ name, ok, detail }: { name: string; ok: boolean; detail: string }) {
  return (
    <li className="flex items-center justify-between gap-4 py-3">
      <div className="min-w-0">
        <div className="text-sm font-medium">{name}</div>
        <div className="text-xs text-muted">{detail}</div>
      </div>
      <Badge tone={ok ? "good" : "warn"}>{ok ? "Running" : "Not running"}</Badge>
    </li>
  );
}

export function SettingsPage() {
  const { user } = useAuth();
  const health = useAsync(async () => {
    const [live, ready] = await Promise.all([getLiveness(), getReadiness()]);
    return { live, ready };
  }, []);

  return (
    <>
      <PageHeader eyebrow="Settings" title="Account and system" />

      <section className="card p-5">
        <h2 className="text-base font-semibold">Account</h2>
        <dl className="mt-4 grid gap-x-6 gap-y-4 sm:grid-cols-3">
          <div>
            <dt className="eyebrow">Name</dt>
            <dd className="mt-1 text-sm">{user?.full_name}</dd>
          </div>
          <div>
            <dt className="eyebrow">Email</dt>
            <dd className="mt-1 break-all font-mono text-sm">{user?.email}</dd>
          </div>
          <div>
            <dt className="eyebrow">Member since</dt>
            <dd className="mt-1 text-sm">{formatDate(user?.created_at)}</dd>
          </div>
        </dl>
      </section>

      <section className="card mt-6 p-5">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-base font-semibold">System status</h2>
          <button type="button" className="btn btn-secondary" onClick={() => void health.reload()} disabled={health.loading}>
            <FiRefreshCw aria-hidden className={health.loading ? "animate-spin" : ""} /> Check again
          </button>
        </div>

        {health.loading && !health.data ? (
          <Spinner label="Checking services" />
        ) : health.error && !health.data ? (
          <div className="mt-4">
            <ErrorNotice message={health.error} onRetry={() => void health.reload()} />
          </div>
        ) : (
          health.data && (
            <>
              <ul className="mt-2 divide-y divide-line">
                <Row name="API" ok detail={`${health.data.live.service} ${health.data.live.version}`} />
                <Row name="MongoDB" ok={health.data.ready.checks.mongodb.ok} detail="Stores accounts, projects and evidence" />
                <Row name="Redis" ok={health.data.ready.checks.redis.ok} detail="Coordinates background work" />
                <Row
                  name="Background worker"
                  ok={health.data.ready.checks.worker.ok}
                  detail={
                    health.data.ready.checks.worker.last_heartbeat
                      ? `Last heartbeat ${formatDateTime(health.data.ready.checks.worker.last_heartbeat)}`
                      : "No heartbeat received"
                  }
                />
              </ul>
              <p className="mt-3 text-xs text-muted">Checked {formatDateTime(health.data.ready.time)}</p>
            </>
          )
        )}
      </section>
    </>
  );
}
