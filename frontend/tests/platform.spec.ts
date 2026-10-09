import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

import { defaultState, mockApi, projectUrl } from "./mock-api";
import { clone, emptyState, full, insufficient, makeJob, mockPlatform, platformState } from "./mock-platform";
import type { PlatformState } from "./mock-platform";

async function open(page: Page, path: string, state: PlatformState = platformState()) {
  await mockApi(page, defaultState({ analysed: state.analysed }));
  await mockPlatform(page, state);
  await page.goto(path.startsWith("/dashboard") ? path : projectUrl(path));
  return state;
}

/** Things no page may say: the platform never confirms an exploit, forecasts an attack, judges a person or certifies anything. */
const OVERCLAIMS = /exploit (is )?confirmed: yes|will be (exploited|attacked|compromised)|guaranteed|zero-day|malicious|poison-free|certified|is safe\b/i;
const content = (page: Page) => page.getByTestId("project-content");

test.describe("navigation", () => {
  test("every layer is reachable from the project tabs", async ({ page }) => {
    await open(page, "/dependencies");
    const tabs = page.getByRole("navigation", { name: "Project sections" });
    for (const [label, path, testId] of [["Trust", "trust", "trust-job"], ["Attack paths", "attack-paths", "attack-path-job"], ["Maintainers", "maintainers", "maintainer-job"],
      ["Commits", "commits", "commit-job"], ["AI analysis", "ai-analysis", "ai-job"], ["Dataset", "dataset", "dataset-job"], ["Report", "report", "report"]] as const) {
      await tabs.getByRole("link", { name: label, exact: true }).click();
      await expect(page).toHaveURL(new RegExp(`/${path}$`));
      await expect(page.getByTestId(testId)).toBeVisible();
    }
  });

  test("the project overview links to each layer and says what is not built", async ({ page }) => {
    await open(page, "");
    const layers = page.getByTestId("layer-links");
    for (const name of ["Trust score", "Attack-path simulation", "Maintainer behaviour", "Commit behaviour", "Cross-layer AI reasoning", "Dataset quality", "Report"]) {
      await expect(layers.getByRole("link", { name })).toBeVisible();
    }
    await expect(layers).toContainText("Out of scope · static analysis only");
  });
});

test.describe("attack paths page", () => {
  test("before a simulation it shows no path and no figure", async ({ page }) => {
    await open(page, "/attack-paths", emptyState());
    await expect(page.getByTestId("attack-path-job").getByText("Not run")).toBeVisible();
    await expect(page.getByTestId("analysis-not-available")).toContainText("which is not the same as there being none");
    await expect(page.getByTestId("needs-scan")).toContainText("Run a vulnerability check");
    await expect(page.getByRole("button", { name: "Start simulation" })).toBeDisabled();
    for (const id of ["attack-summary", "attack-graph", "attack-path-table"]) await expect(page.getByTestId(id)).toHaveCount(0);
  });

  test("a project without an inventory is sent to the analysis first", async ({ page }) => {
    await open(page, "/attack-paths", emptyState({ analysed: false }));
    await expect(page.getByTestId("not-analysed")).toBeVisible();
  });

  test("the summary, the table and the graph show the stored paths", async ({ page }) => {
    await open(page, "/attack-paths");
    const summary = page.getByTestId("attack-summary");
    for (const [label, value] of [["Paths", "7"], ["Supported", "1"], ["Potential", "0"], ["Unknown", "6"]]) {
      await expect(summary.getByText(label, { exact: true }).locator("..")).toContainText(value);
    }
    await expect(page.getByTestId("attack-path-row")).toHaveCount(7);
    const first = page.getByTestId("attack-path-row").first();
    await expect(first).toContainText("requests");
    await expect(first).toContainText("TEST-REQ-GET");
    await expect(first).toContainText("Supported path");
    await expect(page.getByTestId("attack-meaning")).toContainText("No path was exercised");
    const graph = page.getByTestId("attack-graph").first();
    await expect(graph.locator('[data-testid="attack-node"][data-stage="ENTRY"]')).toHaveCount(1);
    await expect(graph.locator('[data-testid="attack-node"][data-stage="VULNERABILITY"]')).toHaveCount(7);
    await expect(graph.locator('[data-testid="attack-node"][data-stage="IMPACT"]')).toHaveCount(7);
    await expect(page.getByTestId("attack-graph-panel")).toContainText("7 of 7 path(s) drawn");
  });

  test("the status filter narrows the table", async ({ page }) => {
    await open(page, "/attack-paths");
    await page.getByLabel("Filter by status").selectOption("SUPPORTED_PATH");
    await expect(page.getByTestId("attack-path-row")).toHaveCount(1);
    await page.getByLabel("Filter by status").selectOption("POTENTIAL_PATH");
    await expect(page.getByTestId("attack-path-table")).toContainText("No path has this status.");
  });

  test("a path shows its stages, score, evidence and explanation", async ({ page }) => {
    await open(page, "/attack-paths");
    await page.getByTestId("attack-path-row").first().getByRole("button").click();
    const detail = page.getByTestId("attack-path-detail");
    const stages = detail.getByTestId("path-stages");
    for (const text of ["Source", "Dependency", "Vulnerability", "Reachable component", "Downstream impact", "app/client.py:5", "TEST-REQ-GET"]) await expect(stages).toContainText(text);
    await expect(detail.getByTestId("path-score")).toContainText("× 1 (reachability reachable) ×");
    await expect(detail).toContainText("exploit confirmed: no");
    await expect(detail.getByTestId("path-explanation")).toContainText("No exploit was attempted");
    await expect(detail.getByTestId("path-explanation").locator('[data-basis="OBSERVED"]').first()).toBeVisible();
    await expect(detail.getByTestId("path-evidence")).toContainText("advisory match");
    await expect(detail.getByTestId("path-evidence")).toContainText("app/client.py:5");
    await expect(detail.locator('[data-basis="RECOMMENDED"]').first()).toBeVisible();
    await detail.getByRole("button", { name: "Close" }).click();
    await expect(detail).toHaveCount(0);
  });

  test("an unknown path says reachability was not established", async ({ page }) => {
    await open(page, "/attack-paths");
    await page.locator('[data-testid="attack-path-row"][data-status="UNKNOWN_PATH"]').first().getByRole("button").click();
    await expect(page.getByTestId("path-stages")).toContainText(/not established \((unsupported|unknown)\)/);
  });

  test("the what-if reports what fixing a package would remove", async ({ page }) => {
    const state = await open(page, "/attack-paths");
    await page.getByLabel("What if a package were fixed?").selectOption("npm:qs@6.7.0");
    const result = page.getByTestId("what-if-result");
    await expect(result).toContainText("Without qs@6.7.0: 3 of 7 path(s) would no longer exist");
    await expect(result).toContainText("only a new analysis can show");
    expect(state.requests.some((request) => request.path.endsWith("/attack-paths/graph") && request.query.without === "npm:qs@6.7.0")).toBe(true);
  });

  test("running the simulation shows progress and then the paths", async ({ page }) => {
    const state = emptyState({ jobs: [null], startJobs: [makeJob("attack_paths", "queued"), makeJob("attack_paths", "running"), makeJob("attack_paths", "completed")], afterAnalysis: clone(full) });
    state.data.attack_paths.has_vulnerability_scan = true;
    await open(page, "/attack-paths", state);
    await page.getByRole("button", { name: "Start simulation" }).click();
    const job = page.getByTestId("attack-path-job");
    await expect(job.getByText("Queued")).toBeVisible();
    await expect(job.getByText("Completed")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("attack-path-row")).toHaveCount(7);
  });

  test("a failed simulation is reported and a refused start explained", async ({ page }) => {
    await open(page, "/attack-paths", platformState({ jobs: [makeJob("attack_paths", "failed")], startStatus: 409 }));
    await expect(page.getByTestId("attack-path-job").getByRole("alert")).toContainText("Any paths shown are from an earlier run");
    await page.getByRole("button", { name: "Run again" }).click();
    await expect(page.getByTestId("attack-path-job")).toContainText("Another job is already queued or running");
  });

  test("a server error is shown with a retry, and nothing overclaims", async ({ page }) => {
    const state = platformState({ failures: { "/attack-paths": 500 } });
    await open(page, "/attack-paths", state);
    await expect(page.getByRole("alert")).toContainText("Internal server error");
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("attack-path-row")).toHaveCount(7);
    await expect(content(page)).not.toContainText(OVERCLAIMS);
  });
});

test.describe("maintainer intelligence page", () => {
  test("before an analysis every indicator is unknown and nothing is shown", async ({ page }) => {
    await open(page, "/maintainers", emptyState());
    await expect(page.getByTestId("analysis-not-available")).toContainText("every indicator is unknown");
    await expect(page.getByTestId("maintainer-meaning")).toContainText("no indicator is a judgement about a person");
    for (const id of ["maintainer-summary", "indicators", "contributors"]) await expect(page.getByTestId(id)).toHaveCount(0);
  });

  test("the profile, the timeline and the indicators are shown", async ({ page }) => {
    const state = platformState();
    const indicators = state.data.maintainers.profile.anomaly_indicators;
    indicators[3] = { ...indicators[3], status: "UNKNOWN", strength: 0, detail: "Release data could not be collected from GitHub.", evidence: {} };
    await open(page, "/maintainers", state);
    const summary = page.getByTestId("maintainer-summary");
    await expect(summary.getByText("Contributors", { exact: true }).locator("..")).toContainText("2");
    await expect(summary).toContainText("in 40 observed commit(s)");
    await expect(page.getByTestId("activity-chart")).toBeVisible();
    await expect(page.getByTestId("indicator")).toHaveCount(7);
    const concentration = page.locator('[data-testid="indicator"][data-type="CONTRIBUTOR_CONCENTRATION"]');
    await expect(concentration).toHaveAttribute("data-status", "OBSERVED");
    await expect(concentration).toContainText("alice authored");
    await concentration.getByRole("button", { name: "Evidence" }).click();
    await expect(concentration.getByTestId("indicator-evidence")).toContainText("top share");
    const unknown = page.locator('[data-testid="indicator"][data-status="UNKNOWN"]');
    await expect(unknown).toHaveCount(1);
    await expect(unknown).toContainText("Unknown");
    await expect(unknown).toContainText("could not be collected");
  });

  test("a contributor's detail shows activity without any e-mail address", async ({ page }) => {
    await open(page, "/maintainers");
    await expect(page.getByTestId("contributor-row")).toHaveCount(2);
    await page.locator('[data-testid="contributor-row"][data-name="alice"]').getByRole("button").click();
    const detail = page.getByTestId("contributor-detail");
    await expect(detail).toContainText("Commits observed");
    await expect(detail).toContainText("GitHub account");
    await expect(detail).toContainText("Sample commits");
    await expect(content(page)).not.toContainText(/@example\.com/);
  });

  test("unavailable GitHub data is said to be unavailable, not clean", async ({ page }) => {
    const state = platformState();
    state.data.maintainers.profile = { ...state.data.maintainers.profile, data_status: "UNAVAILABLE", unavailable: [{ source: "commits", code: "RATE_LIMITED", reason: "limit" }] };
    await open(page, "/maintainers", state);
    await expect(page.getByTestId("maintainer-unavailable")).toContainText("commits: RATE_LIMITED");
    await expect(page.getByTestId("maintainer-unavailable")).toContainText("nothing was estimated in its place");
    await expect(page.getByTestId("indicators")).toHaveCount(0);
  });

  test("a partial job explains what was missing and no page labels a person", async ({ page }) => {
    await open(page, "/maintainers", platformState({ jobs: [makeJob("maintainers", "partial", { error: { code: "GITHUB_DATA_INCOMPLETE", message: "GitHub data could not be collected for: releases." } })] }));
    await expect(page.getByTestId("job-partial")).toContainText("GitHub data could not be collected for: releases.");
    await expect(content(page)).not.toContainText(/malicious|suspicious|untrustworthy|bad actor/i);
  });
});

test.describe("real-time behaviour page", () => {
  test("before an analysis there are no events and no scores", async ({ page }) => {
    await open(page, "/commits", emptyState());
    await expect(page.getByTestId("analysis-not-available")).toContainText("which is not the same as there being none");
    await expect(page.getByTestId("monitoring")).toContainText("no webhook is registered");
    for (const id of ["commit-summary", "commit-timeline", "commit-table", "security-events"]) await expect(page.getByTestId(id)).toHaveCount(0);
  });

  test("the timeline, the events and the commits are shown", async ({ page }) => {
    await open(page, "/commits");
    await expect(page.getByTestId("commit-summary").getByText("Commits analysed", { exact: true }).locator("..")).toContainText("30");
    await expect(page.getByTestId("commit-summary")).toContainText("10 newer commit(s) still waiting");
    await expect(page.getByTestId("commit-timeline-chart")).toBeVisible();
    await expect(page.getByTestId("commit-row")).toHaveCount(30);
    const events = page.getByTestId("security-event");
    await expect(events).toHaveCount(3);
    await expect(page.locator('[data-testid="security-event"][data-type="SECRET_LIKE_PATTERN"]')).toContainText("The value is not stored");
    await expect(events.first()).toContainText("not a confirmed incident");
    await expect(page.getByTestId("commit-meaning")).toContainText("not a verdict on the change or on its author");
  });

  test("a commit shows changed files, findings with masked excerpts and score factors", async ({ page }) => {
    await open(page, "/commits");
    await page.getByLabel("Filter by indicator").selectOption("SECRET_LIKE_PATTERN");
    await expect(page.getByTestId("commit-row")).toHaveCount(1);
    await page.getByTestId("commit-row").getByRole("button").click();
    const detail = page.getByTestId("commit-detail");
    await expect(detail.getByTestId("changed-files")).toContainText("scripts/release.py");
    await expect(detail.getByTestId("changed-files")).toContainText(".github/workflows/release.yml");
    const secret = detail.locator('[data-testid="commit-finding"][data-rule="github_token"]');
    await expect(secret).toContainText("The value is not stored");
    await expect(secret.getByTestId("finding-excerpt")).toContainText("ghp_***(40 chars)");
    await expect(detail.locator('[data-testid="commit-finding"][data-rule="shell_enabled"]')).toContainText("shell=True");
    await expect(detail.locator('[data-testid="commit-finding"][data-rule="ci_pipeline_changed"] [data-basis="OBSERVED"]')).toBeVisible();
    await expect(detail.getByTestId("anomaly-factors").locator("tbody tr")).toHaveCount(6);
    await expect(detail.getByTestId("anomaly-factors")).toContainText("security signals");
    await expect(detail).not.toContainText(/ghp_[A-Za-z0-9]{30,}/);
  });

  test("monitoring can be switched on and the request carries only the flag", async ({ page }) => {
    const state = await open(page, "/commits");
    const toggle = page.getByLabel("Check this repository for new commits periodically");
    await expect(toggle).not.toBeChecked();
    await toggle.check();
    await expect(toggle).toBeChecked();
    const request = state.requests.find((item) => item.path.endsWith("/commits/monitoring"));
    expect(request?.body).toEqual({ enabled: true });
  });

  test("when GitHub could not be read nothing is assumed about the commits", async ({ page }) => {
    const state = emptyState();
    state.data.commits.analysis = { ...clone(full.commits.analysis), summary: { ...full.commits.analysis.summary, data_status: "UNAVAILABLE", analysed: 0 } };
    await open(page, "/commits", state);
    await expect(page.getByTestId("analysis-not-available")).toContainText("Nothing is assumed about the commits that could not be read");
  });

  test("checking for new commits shows progress", async ({ page }) => {
    await open(page, "/commits", platformState({ startJobs: [makeJob("commits", "queued"), makeJob("commits", "running"), makeJob("commits", "completed")] }));
    await page.getByRole("button", { name: "Check for new commits" }).click();
    await expect(page.getByTestId("commit-job").getByText("Queued")).toBeVisible();
    await expect(page.getByTestId("commit-job").getByText("Completed")).toBeVisible({ timeout: 15_000 });
    await expect(content(page)).not.toContainText(OVERCLAIMS);
  });
});

test.describe("AI security analysis page", () => {
  test("before a run there are no findings", async ({ page }) => {
    await open(page, "/ai-analysis", emptyState());
    await expect(page.getByTestId("analysis-not-available")).toContainText("No reasoning run exists");
    await expect(page.getByTestId("ai-meaning")).toContainText("it is not proof of an attack");
    await expect(page.getByTestId("ai-finding")).toHaveCount(0);
  });

  test("findings are listed most severe first with measured grounding", async ({ page }) => {
    await open(page, "/ai-analysis");
    const summary = page.getByTestId("ai-summary");
    await expect(summary.getByText("Evidence grounding", { exact: true }).locator("..")).toContainText("100%");
    await expect(summary.getByText("Unsupported-claim rate", { exact: true }).locator("..")).toContainText("0%");
    await expect(summary).toContainText("rules only, no model");
    const findings = page.getByTestId("ai-finding");
    await expect(findings).toHaveCount(full.ai.items.length);
    await expect(findings.first()).toHaveAttribute("data-category", "HIGH_PRIORITY_CORRELATED_RISK");
    await expect(findings.first()).toContainText("requests");
  });

  test("a finding shows labelled statements, a recommendation, layers and its evidence", async ({ page }) => {
    await open(page, "/ai-analysis");
    const finding = page.locator('[data-testid="ai-finding"][data-category="HIGH_PRIORITY_CORRELATED_RISK"]');
    await expect(finding.locator('[data-testid="finding-statement"][data-basis="OBSERVED"]').first()).toContainText("TEST-REQ-GET lists requests");
    await expect(finding.locator('[data-testid="finding-statement"][data-basis="DERIVED"]').first()).toBeVisible();
    await expect(finding.locator('[data-testid="finding-statement"][data-basis="RECOMMENDED"]')).toContainText("Upgrade requests");
    await expect(finding.getByTestId("finding-layer").first()).toBeVisible();
    for (const statement of await finding.getByTestId("finding-statement").all()) await expect(statement).toContainText(/\[E\d+\]/);
    await finding.getByRole("button", { name: "Evidence and reasoning" }).click();
    await expect(finding.getByTestId("finding-evidence")).toContainText("vulnerability_matches/");
    await expect(finding.getByTestId("finding-reasoning")).toContainText("held — known vulnerability");
    await expect(finding.getByTestId("finding-reasoning")).toContainText("Confidence = weakest cited evidence");
  });

  test("the severity filter and the missing-layer notice", async ({ page }) => {
    const state = platformState();
    state.data.ai.analysis.summary.layers_missing = ["reachability", "dataset"];
    await open(page, "/ai-analysis", state);
    await expect(page.getByTestId("ai-missing-layers")).toContainText("reachability, dataset. What those layers would show is unknown.");
    const total = full.ai.items.length;
    const high = full.ai.items.filter((item: { severity: string }) => ["HIGH", "CRITICAL"].includes(item.severity)).length;
    await page.getByLabel("Minimum severity").selectOption("HIGH");
    await expect(page.getByTestId("ai-finding")).toHaveCount(high);
    expect(high).toBeLessThan(total);
    await expect(content(page)).not.toContainText(OVERCLAIMS);
  });

  test("no secret-like value reaches the page", async ({ page }) => {
    await open(page, "/ai-analysis");
    await expect(page.locator('[data-testid="ai-finding"][data-category="SECRET_EXPOSURE_REVIEW"]')).toContainText("the value itself is not stored");
    await expect(content(page)).not.toContainText(/ghp_[A-Za-z0-9]{30,}/);
  });
});

test.describe("dataset trust page", () => {
  test("before a validation the quality is unknown", async ({ page }) => {
    await open(page, "/dataset", emptyState());
    await expect(page.getByTestId("analysis-not-available")).toContainText("its quality is unknown");
    await expect(page.getByTestId("dataset-limitation")).toContainText("cannot establish that the data is free of deliberate manipulation");
    await expect(page.getByTestId("dataset-summary")).toHaveCount(0);
  });

  test("status, score, factors, provenance, balance and history are shown", async ({ page }) => {
    await open(page, "/dataset");
    const summary = page.getByTestId("dataset-summary");
    await expect(summary).toContainText("LOW CONFIDENCE");
    await expect(summary).toContainText("Only 9 record(s); at least 10 are needed.");
    await expect(page.getByTestId("quality-factor")).toHaveCount(7);
    await expect(page.locator('[data-testid="quality-factor"][data-factor="integrity"]')).toContainText("100%");
    await expect(page.getByTestId("provenance")).toContainText("7 analysis layer(s) contributed");
    await expect(page.getByTestId("provenance-missing")).toHaveCount(0);
    await expect(page.getByTestId("integrity")).toContainText("VERIFIED");
    await expect(page.getByTestId("integrity")).toContainText("Version chain intact");
    await expect(page.getByTestId("class-chart")).toBeVisible();
    await expect(page.getByTestId("class-distribution")).toContainText("4 true, 5 false, 0 unknown");
    await expect(page.getByTestId("suspicious-records")).toContainText("No record breaks the schema or contradicts itself.");
    await expect(page.getByTestId("validation-row")).toHaveCount(1);
    await expect(page.getByTestId("dataset-versions")).toContainText("Version 1 · 9 record(s)");
  });

  test("tampering found on read is shown prominently", async ({ page }) => {
    const state = platformState();
    state.data.dataset_quality.integrity_now = { status: "MISMATCH", records_checked: 9, altered_count: 1, altered_records: ["npm:qs@6.7.0"], chain_intact: true };
    state.data.datasets.chain_intact = false;
    await open(page, "/dataset", state);
    await expect(page.getByTestId("integrity")).toContainText("MISMATCH");
    await expect(page.getByTestId("integrity")).toContainText("Altered since they were written: npm:qs@6.7.0");
    await expect(page.getByTestId("integrity")).toContainText("BROKEN");
  });

  test("missing layers, suspicious records and unknown factors are listed", async ({ page }) => {
    const state = platformState();
    const quality = state.data.dataset_quality.quality;
    quality.provenance.source_layers_missing = ["reachability", "attack_paths"];
    quality.suspicious_records = [{ record_id: "npm:x@1", problems: [{ kind: "INCONSISTENT", rule: "label.vulnerable", detail: "The label 'vulnerable' is true but 0 advisory match(es) are recorded." }] }];
    quality.factors[5] = { ...quality.factors[5], status: "UNKNOWN", value: null, contribution: null };
    quality.completeness.missing_by_field = { fragility_score: 9 };
    await open(page, "/dataset", state);
    await expect(page.getByTestId("provenance-missing")).toContainText("No data from: reachability, attack paths.");
    await expect(page.getByTestId("suspicious-records")).toContainText("npm:x@1");
    await expect(page.locator('[data-testid="quality-factor"][data-status="UNKNOWN"]')).toContainText("unknown");
    await expect(page.getByTestId("missing-data")).toContainText("fragility score: missing in 9 record(s)");
    await expect(content(page)).not.toContainText(OVERCLAIMS);
  });
});

test.describe("trust dashboard", () => {
  test("without a trust analysis there is no score", async ({ page }) => {
    await open(page, "/trust", emptyState());
    await expect(page.getByTestId("analysis-not-available")).toContainText("There is no score to show, and none is estimated.");
    for (const id of ["trust-headline", "trust-score", "insufficient-data", "trust-components"]) await expect(page.getByTestId(id)).toHaveCount(0);
    await expect(content(page)).not.toContainText(/\b\d{1,3}(\.\d)? \/ 100/);
  });

  test("insufficient evidence is stated in words, with no number presented as a score", async ({ page }) => {
    const state = emptyState();
    state.data.trust = clone(insufficient.trust);
    state.data.trust_explanation = clone(insufficient.explanation);
    await open(page, "/trust", state);
    const notice = page.getByTestId("insufficient-data");
    await expect(notice).toContainText("INSUFFICIENT DATA");
    await expect(notice).toContainText("would present missing evidence as if it were good news");
    await expect(notice).toContainText("30% of the model's weight");
    await expect(page.getByTestId("trust-score")).toHaveCount(0);
    await expect(page.getByTestId("risk-score")).toHaveCount(0);
    await expect(page.locator('[data-testid="trust-component"][data-status="UNKNOWN"]')).toHaveCount(8);
    await expect(page.locator('[data-testid="trust-component"][data-status="UNKNOWN"]').first()).toContainText("Unknown");
    await expect(page.getByTestId("trust-recommendations")).toContainText("Until then");
    await expect(page.getByTestId("trust-worked")).toHaveCount(0);
  });

  test("a scored result shows trust, risk, confidence, components and the calculation", async ({ page }) => {
    await open(page, "/trust");
    const trust = full.trust.trust;
    await expect(page.getByTestId("trust-score")).toContainText(trust.trust_score.toFixed(1));
    await expect(page.getByTestId("risk-score")).toContainText(trust.risk_score.toFixed(1));
    await expect(page.getByTestId("trust-confidence")).toContainText(`${Math.round(trust.confidence * 100)}%`);
    await expect(page.getByTestId("trust-component")).toHaveCount(10);
    await expect(page.locator('[data-testid="trust-component"][data-component="vulnerability_exposure"]')).toContainText("15%");
    await expect(page.getByTestId("contribution-chart")).toBeVisible();
    await expect(page.getByTestId("trust-worked")).toContainText(`= ${trust.risk_score}; trust = 100 − ${trust.risk_score} = ${trust.trust_score}`);
    await expect(page.getByTestId("weights-statement")).toHaveText("These weights are expert-defined initial weights and are not statistically trained.");
    await expect(page.getByTestId("trust-meaning")).toContainText("It is not a certification");
    await expect(page.getByTestId("trust-top-risks").locator("li").first()).toContainText("Vulnerability exposure");
    await expect(page.getByTestId("trust-recommendations").locator('[data-basis="RECOMMENDED"]').first()).toBeVisible();
    await expect(page.getByTestId("trust-evidence").locator("li")).toHaveCount(11);
  });

  test("the trend lists every result and leaves a gap for the one without a score", async ({ page }) => {
    await open(page, "/trust");
    await expect(page.getByTestId("trust-trend-chart")).toBeVisible();
    const history = page.getByTestId("trust-history").locator("li");
    await expect(history).toHaveCount(2);
    await expect(history.first()).toContainText("insufficient data");
    await expect(history.last()).toContainText(`trust ${full.trust.trust.trust_score}`);
  });

  test("a result older than the layers says so", async ({ page }) => {
    const state = platformState();
    state.data.trust.up_to_date = false;
    await open(page, "/trust", state);
    await expect(page.getByTestId("trust-outdated")).toContainText("Recalculate to include it");
  });

  test("component names link to their layer and nothing overclaims", async ({ page }) => {
    await open(page, "/trust");
    await page.locator('[data-testid="trust-component"][data-component="attack_path_risk"]').getByRole("link").click();
    await expect(page).toHaveURL(/\/attack-paths$/);
    await page.goBack();
    await expect(content(page)).not.toContainText(OVERCLAIMS);
  });

  test("calculating shows progress and then the result", async ({ page }) => {
    await open(page, "/trust", emptyState({ startJobs: [makeJob("trust", "queued"), makeJob("trust", "running"), makeJob("trust", "completed")], afterAnalysis: clone(full) }));
    await page.getByRole("button", { name: "Calculate trust" }).click();
    await expect(page.getByTestId("trust-job").getByText("Completed")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByTestId("trust-score")).toBeVisible();
  });
});

test.describe("dashboards", () => {
  test("the executive dashboard shows the score, the numbers, findings and next steps", async ({ page }) => {
    await open(page, "/dashboard");
    const dashboards = page.getByTestId("project-dashboards");
    await expect(dashboards.getByTestId("executive-dashboard")).toBeVisible();
    await expect(dashboards.getByTestId("trust-score")).toContainText(full.trust.trust.trust_score.toFixed(1));
    const numbers = dashboards.getByTestId("executive-numbers");
    for (const [label, value] of [["Dependencies", "9"], ["Known vulnerabilities", "7"], ["Reached by code", "1"], ["Attack paths", "7"], ["Events to review", "3"]]) {
      await expect(numbers.getByText(label, { exact: true }).locator("..")).toContainText(value);
    }
    await expect(dashboards.getByTestId("trust-trend-chart")).toBeVisible();
    await expect(dashboards.getByTestId("contribution-chart")).toBeVisible();
    await expect(dashboards.getByTestId("executive-findings")).toContainText("HIGH_PRIORITY_CORRELATED_RISK");
    await expect(dashboards.getByTestId("executive-recommendations").locator('[data-basis="RECOMMENDED"]').first()).toBeVisible();
    await expect(dashboards.locator('[data-testid="layer-status"] [data-status="ANALYSED"]')).toHaveCount(11);
  });

  test("the technical dashboard draws every chart from stored results", async ({ page }) => {
    await open(page, "/dashboard");
    await page.getByRole("tab", { name: "Technical" }).click();
    const technical = page.getByTestId("technical-dashboard");
    for (const id of ["vulnerability-chart", "dependency-risk-chart", "fragility-chart", "attack-path-chart", "commit-timeline-chart", "reachability-chart"]) {
      await expect(technical.getByTestId(id)).toBeVisible();
    }
    await expect(technical.getByTestId("panel-inventory")).toContainText("9 (5 direct, 4 transitive)");
    await expect(technical.getByTestId("panel-inventory")).toContainText("verified");
    await expect(technical.getByTestId("chart-not-available")).toHaveCount(0);
  });

  test("the research dashboard shows what was measured and what was not", async ({ page }) => {
    await open(page, "/dashboard");
    await page.getByRole("tab", { name: "Research" }).click();
    const research = page.getByTestId("research-dashboard");
    await expect(research.getByTestId("research-measured").getByText("Evidence grounding", { exact: true }).locator("..")).toContainText("100%");
    await expect(research.getByTestId("research-models")).toContainText("trust: trust-v1");
    await expect(research.getByTestId("research-weights-statement")).toHaveText("These weights are expert-defined initial weights and are not statistically trained.");
    await expect(research.getByTestId("research-timings")).toContainText("A measurement, not a benchmark.");
    const rows = research.getByTestId("evaluation-row");
    await expect(rows.first()).toBeVisible();
    await expect(research.locator('[data-testid="evaluation-row"][data-status="EVALUATED"]')).toHaveCount(0);
    await expect(research.getByTestId("research-evaluation")).toContainText("NOT EVALUATED");
    await expect(research.getByTestId("research-evaluation")).not.toContainText(/0\.\d+ \(/);
  });

  test("an unanalysed project shows statuses and placeholders instead of empty charts", async ({ page }) => {
    await open(page, "/dashboard", emptyState());
    const dashboards = page.getByTestId("project-dashboards");
    await expect(dashboards.getByTestId("no-trust-score")).toContainText("No trust score yet");
    await expect(dashboards.getByTestId("executive-numbers").getByText("Known vulnerabilities", { exact: true }).locator("..")).toContainText("not checked");
    await expect(dashboards.locator('[data-testid="layer-status"] [data-status="NOT_ANALYSED"]')).toHaveCount(10);
    await page.getByRole("tab", { name: "Technical" }).click();
    await expect(page.getByTestId("chart-not-available")).toHaveCount(6);
    for (const id of ["vulnerability-chart", "fragility-chart", "attack-path-chart"]) await expect(page.getByTestId(id)).toHaveCount(0);
    await expect(page.getByTestId("dashboards")).not.toContainText(OVERCLAIMS);
  });

  test("the project selector names the state of each project", async ({ page }) => {
    await open(page, "/dashboard");
    await expect(page.getByTestId("dashboard-project").locator("option")).toHaveText([`ShadowWatch — trust ${full.trust.trust.trust_score}`]);
  });
});

test.describe("report page", () => {
  test("the report has seventeen sections and every statement carries a basis and references", async ({ page }) => {
    await open(page, "/report");
    const sections = page.getByTestId("report-section");
    await expect(sections).toHaveCount(17);
    await expect(sections.first()).toContainText("1. Executive Summary");
    await expect(sections.last()).toContainText("17. Limitations");
    const statements = page.getByTestId("report-statement");
    const count = await statements.count();
    expect(count).toBe(full.report.statement_count);
    for (const index of [0, 5, Math.floor(count / 2), count - 1]) {
      await expect(statements.nth(index).locator("[data-basis]")).toBeVisible();
      await expect(statements.nth(index).getByTestId("report-refs")).toContainText(/\[R\d+\]/);
    }
    await expect(page.getByTestId("evidence-index").locator("tbody tr")).toHaveCount(full.report.evidence.length);
    await expect(page.getByTestId("report-meaning")).toContainText("section 15 lists what each reference points to");
  });

  test("a report on partial evidence marks the missing sections", async ({ page }) => {
    await open(page, "/report", emptyState());
    await expect(page.locator('[data-testid="report-section"][data-section="attack_paths"]')).toHaveAttribute("data-available", "false");
    await expect(page.locator('[data-testid="report-section"][data-section="attack_paths"]')).toContainText("the absence of findings here is not a clean result");
    await expect(page.locator('[data-testid="report-section"][data-section="trust_score"]')).toContainText("No trust analysis has been run");
  });

  test("the limitations and the weights caveat are part of the report", async ({ page }) => {
    await open(page, "/report");
    const limitations = page.locator('[data-testid="report-section"][data-section="limitations"]');
    await expect(limitations).toContainText("expert-defined initial weights and are not statistically trained");
    await expect(limitations).toContainText("No repository code was executed");
    await expect(content(page)).not.toContainText(OVERCLAIMS);
  });

  test("the report can be downloaded as Markdown", async ({ page }) => {
    const state = await open(page, "/report");
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download Markdown" }).click();
    expect((await download).suggestedFilename()).toMatch(/^trustchain-x-report-.*\.md$/);
    expect(state.requests.some((request) => request.path.endsWith("/report") && request.query.format === "markdown")).toBe(true);
  });

  test("a report that cannot be built shows the error", async ({ page }) => {
    await open(page, "/report", platformState({ failures: { "/report": 500 } }));
    await expect(page.getByRole("alert")).toContainText("Internal server error");
    await expect(page.getByTestId("report-section")).toHaveCount(0);
  });
});
