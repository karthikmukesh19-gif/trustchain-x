import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

import { defaultState, mockApi, projectUrl } from "./mock-api";
import { clone, fragilityOnlyState, idOf, intelligenceState, makeIntelligenceJob, mockIntelligence, predictive } from "./mock-intelligence";
import type { IntelligenceState } from "./mock-intelligence";

async function open(page: Page, state: IntelligenceState) {
  await mockApi(page, defaultState({ analysed: state.analysed }));
  await mockIntelligence(page, state);
  await page.goto(projectUrl("/fragility"));
}

const row = (page: Page, name: string) => page.locator(`[data-testid="risk-row"][data-name="${name}"]`);
const NAMES = ["requests", "debug", "qs", "ms", "lodash", "body-parser", "express", "morgan", "PyYAML"];
/** Words the page must never use about a dependency: nothing here is a guarantee or a forecast of an attack. */
const OVERCLAIMS = /will be (compromised|exploited|attacked)|guaranteed|zero-day|malicious|trust score|exploitable/i;

test.describe("dependency intelligence page", () => {
  test("is reached from the project tabs", async ({ page }) => {
    await mockApi(page, defaultState());
    await mockIntelligence(page, intelligenceState());
    await page.goto(projectUrl("/dependencies"));
    await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Dependency intelligence" }).click();
    await expect(page).toHaveURL(/\/fragility$/);
    await expect(page.getByTestId("intelligence-job")).toBeVisible();
  });

  test("a project without a dependency inventory is sent to the analysis first", async ({ page }) => {
    await open(page, intelligenceState({ analysed: false, scanned: false, mode: "none", jobs: [null] }));
    await expect(page.getByTestId("not-analysed")).toBeVisible();
    await expect(page.getByTestId("risk-table")).toHaveCount(0);
  });

  test("before any analysis it says 'Analysis not available' and shows no figure at all", async ({ page }) => {
    await open(page, intelligenceState({ mode: "none", jobs: [null] }));
    const job = page.getByTestId("intelligence-job");
    await expect(job.getByText("Not run")).toBeVisible();
    await expect(job.getByRole("button", { name: "Start analysis" })).toBeEnabled();
    await expect(job).toContainText("not predictions of specific vulnerabilities or attacks");
    const empty = page.getByTestId("analysis-not-available");
    await expect(empty).toContainText("Analysis not available");
    await expect(empty).toContainText("A missing figure is not a low one");
    for (const id of ["fragility-overview", "risk-table", "graph-risk-panel", "analysis-changes"]) await expect(page.getByTestId(id)).toHaveCount(0);
    // No score, level or "risk = 0" is invented for an unanalysed snapshot.
    await expect(page.getByTestId("project-content")).not.toContainText(/\b\d+\.\d\b|\bLow\b|\bMedium\b|\bHigh\b|of 100|Risk\s*=\s*0/);
  });

  test("without a vulnerability check only fragility can be analysed, and the reason is given", async ({ page }) => {
    const state = intelligenceState({ scanned: false, mode: "none", jobs: [null] });
    await open(page, state);
    await expect(page.getByTestId("needs-scan")).toContainText("has no vulnerability check");
    await expect(page.getByRole("button", { name: "Start analysis" })).toHaveCount(0);
    await page.getByRole("button", { name: "Analyse fragility only" }).click();
    await expect.poll(() => state.requests.filter((r) => r.method === "POST").map((r) => r.path.split("/").slice(-2).join("/"))).toEqual(["fragility/analyze"]);
    await page.getByTestId("needs-scan").getByRole("link", { name: "Go to vulnerabilities" }).click();
    await expect(page).toHaveURL(/\/vulnerabilities$/);
  });

  test("starting an analysis shows queued, progress and then the results", async ({ page }) => {
    const state = intelligenceState({
      mode: "none", jobs: [null],
      startJobs: [makeIntelligenceJob("queued"), makeIntelligenceJob("running"), makeIntelligenceJob("completed")],
      afterAnalysis: { mode: "predictive" },
    });
    await open(page, state);
    const job = page.getByTestId("intelligence-job");
    await job.getByRole("button", { name: "Start analysis" }).click();
    await expect(job.getByText("Queued")).toBeVisible();
    await expect(job.getByText("Looked up 5 of 9 package(s) in their registries")).toBeVisible();
    await expect(job.getByRole("button", { name: "Analysis in progress" })).toBeDisabled();
    for (const stage of ["Measure graph", "Registry metadata", "Score fragility", "Trace exposure", "Indicators"]) {
      await expect(job.getByText(stage, { exact: true })).toBeVisible();
    }
    await expect(page.getByTestId("analysis-not-available")).toBeVisible();          // nothing is shown while it runs
    await expect(job.getByText("Completed")).toBeVisible({ timeout: 15000 });
    await expect(job).toContainText("9 dependencies assessed; 6 indicator(s)");
    await expect(page.getByTestId("risk-row")).toHaveCount(9);
    await expect(job.getByRole("button", { name: "Analyse again" })).toBeEnabled();
    expect(state.requests.filter((r) => r.method === "POST" && r.path.endsWith("/predictive-risk/analyze"))).toHaveLength(1);
  });

  test("the overview reports what was measured and what could not be", async ({ page }) => {
    await open(page, intelligenceState());
    const overview = page.getByTestId("fragility-overview");
    for (const [label, value] of [["Dependencies", "9"], ["Highest predictive risk", "45.2"], ["Highest fragility", "44.9"],
      ["Known-vulnerable packages", "4"], ["Indicators", "6"]]) {
      await expect(overview.locator("div.card", { hasText: label }).first()).toContainText(value);
    }
    await expect(overview.locator("div.card", { hasText: "Known-vulnerable packages" })).toContainText("4 more depend on one");
    await expect(page.getByTestId("model-versions")).toHaveText("fragility-v1 · graph-risk-v1 · dependency-risk-v1 · indicators-v1");
    const notes = page.getByTestId("coverage-notes");
    await expect(notes.getByTestId("unknown-versions")).toContainText("1 of 9 dependencies could not be compared with a latest release (1 not found in their registry)");
    await expect(notes.getByTestId("concentration-note")).toContainText("ms@2.0.0 (4 dependents, 50%)");
    await expect(notes.getByTestId("indicator-counts")).toContainText("Outdated dependency × 3");
    await expect(notes.getByTestId("indicator-counts")).toContainText("Reachable vulnerable dependency × 1");
    await expect(notes.getByTestId("metadata-incomplete")).toHaveCount(0);
    await expect(notes.getByTestId("no-reachability-note")).toHaveCount(0);
    await expect(page.getByTestId("intelligence-meaning")).toContainText(
      "This system estimates dependency fragility and predictive risk indicators. It does not guarantee prediction of future vulnerabilities or attacks.");
    await expect(page.getByTestId("intelligence-meaning")).toContainText("A low score is not a statement that a dependency is safe");
  });

  test("exposure classes and the paths to vulnerable packages come from the dependency graph", async ({ page }) => {
    await open(page, intelligenceState());
    const panel = page.getByTestId("graph-risk-panel");
    for (const [name, count] of [["DIRECT_VULNERABILITY", "4"], ["DEPENDENCY_PROPAGATION", "3"], ["INDIRECT_EXPOSURE", "1"], ["NO_OBSERVED_PROPAGATION", "1"]]) {
      await expect(panel.locator(`[data-classification="${name}"] dd`)).toHaveText(count);
    }
    await expect(panel).toContainText('Only "Known vulnerability" says an advisory matches a package');
    const paths = panel.getByTestId("risk-path");
    await expect(paths).toHaveCount(4);
    await expect(paths.nth(0)).toContainText("project → requests@2.19.1");
    await expect(panel.getByTestId("risk-paths")).toContainText("project → express@4.17.1 → qs@6.7.0");
    await expect(panel.getByTestId("risk-paths")).toContainText("debug@2.6.9 → ms@2.0.0");
    await expect(panel).toContainText("A path here is a dependency relationship, not a code path");
  });

  test("the table lists every dependency with both scores, exposure, reachability and indicators", async ({ page }) => {
    await open(page, intelligenceState());
    await expect(page.getByTestId("risk-table")).toHaveAttribute("data-mode", "predictive");
    await expect(page.getByTestId("risk-row")).toHaveCount(9);
    expect(await page.getByTestId("risk-row").evaluateAll((rows) => rows.map((r) => r.getAttribute("data-name")))).toEqual(NAMES);

    const requests = row(page, "requests");
    for (const text of ["PyPI · direct", "2.19.1"]) await expect(requests).toContainText(text);
    await expect(requests.getByTestId("cell-predictive")).toContainText("45.2");
    await expect(requests.getByTestId("cell-predictive")).toContainText("Medium");
    await expect(requests.getByTestId("cell-predictive")).toContainText("confidence 100%");
    await expect(requests.getByTestId("cell-fragility")).toContainText("13.8");
    await expect(requests.getByTestId("cell-exposure")).toContainText("Known vulnerability");
    await expect(requests.getByTestId("cell-exposure")).toContainText("2 known vulnerabilities");
    await expect(requests.getByTestId("cell-reachability")).toHaveText("Reachable (1)");
    await expect(requests.getByTestId("cell-indicators")).toContainText("Reachable vulnerable dependency");
    await expect(requests.getByTestId("cell-indicators")).toContainText("Outdated dependency");

    // A package that only requires a vulnerable one is not itself called vulnerable.
    const debug = row(page, "debug");
    await expect(debug.getByTestId("cell-exposure")).toHaveText("Requires a vulnerable package");
    await expect(debug.getByTestId("cell-reachability")).toHaveText("—");
    await expect(row(page, "morgan").getByTestId("cell-exposure")).toHaveText("Indirect exposure");
    // npm is not analysed for reachability: the vulnerable package is "unsupported", never "not reachable".
    await expect(row(page, "lodash").getByTestId("cell-reachability")).toHaveText("Unsupported");
    const quiet = row(page, "PyYAML");
    await expect(quiet.getByTestId("cell-exposure")).toHaveText("None observed");
    await expect(quiet.getByTestId("cell-indicators")).toHaveText("None");
    await expect(page.getByTestId("risk-range")).toHaveText("1–9 of 9");
    await expect(page.getByTestId("project-content")).not.toContainText(OVERCLAIMS);
  });

  test("a row expands to the factors behind both scores, which add up to the score", async ({ page }) => {
    await open(page, intelligenceState());
    await row(page, "requests").getByRole("button", { name: "Show evidence for requests" }).click();
    const detail = page.getByTestId("dependency-detail");
    const score = detail.getByTestId("predictive-score");
    await expect(score.getByTestId("predictive-score-value")).toHaveText("45.2");
    await expect(score).toContainText("dependency-risk-v1");
    await expect(score).toContainText("Not a probability");
    await expect(score.locator("tbody tr")).toHaveCount(7);
    const adds = await score.locator("tbody tr td:nth-child(4)").allTextContents();
    expect(adds.reduce((sum, text) => sum + Number(text), 0)).toBeCloseTo(45.2, 1);
    const weights = await score.locator("tbody tr td:nth-child(2)").allTextContents();
    expect(weights.reduce((sum, text) => sum + Number(text), 0)).toBe(100);
    await expect(score.locator('[data-factor="vulnerability_exposure"]')).toContainText("2 known vulnerability match(es); highest published severity HIGH.");
    await expect(score.locator('[data-factor="reachability"]')).toContainText("Affected functionality is statically reached from application code.");

    const fragility = detail.getByTestId("fragility-score");
    await expect(fragility.getByTestId("fragility-score-value")).toHaveText("13.8");
    await expect(fragility).toContainText("Not vulnerability severity");
    await expect(fragility.locator('[data-factor="version_lag"]')).toContainText("Installed 2.19.1 is 13 minor version(s), 3 release(s) behind the latest (2.32.3).");
    await expect(fragility.locator("tbody tr")).toHaveCount(7);
    await expect(fragility.getByTestId("fragility-score-unknown")).toHaveCount(0);
    await expect(score.getByTestId("predictive-score-assumed")).toHaveCount(0);          // every factor of this dependency was measured

    const risk = detail.getByTestId("dependency-graph-risk");
    await expect(risk).toContainText("graph-risk-v1");
    await expect(risk).toContainText("Known vulnerability");
    await expect(risk).toContainText("Reachability (reachable)");
    await expect(risk).toContainText("Influence halves with each dependency step");
  });

  test("health shows registry facts with their source, and indicators carry their evidence", async ({ page }) => {
    await open(page, intelligenceState());
    await row(page, "requests").getByRole("button", { name: "Show evidence for requests" }).click();
    const health = page.getByTestId("health-card");
    await expect(health.getByTestId("version-position")).toContainText("Behind the latest release · 3 release(s) behind · 2400 days between the two releases");
    await expect(health.locator('[data-field="latest_release"]')).toContainText("2.32.3");
    await expect(health.locator('[data-field="release_age_days"]')).toContainText("2900 days");
    await expect(health.locator('[data-field="known_vulnerability_count"]')).toContainText("2");
    await expect(health.locator('[data-field="reachable_vulnerability_count"]')).toContainText("1");
    await expect(health.locator('[data-field="repository_activity"]')).toContainText("Unknown");       // not collected, and said so
    await expect(health.getByTestId("metadata-confidence")).toHaveText("HIGH");
    await expect(health.getByTestId("metadata-source")).toContainText("Release metadata: pypi · collected");

    const indicators = page.getByTestId("indicator");
    await expect(indicators).toHaveCount(2);
    const reachable = page.locator('[data-testid="indicator"][data-type="REACHABLE_VULNERABLE_DEPENDENCY"]');
    await expect(reachable).toContainText("Reachable vulnerable dependency");
    await expect(reachable).toContainText("OBSERVED");
    await expect(reachable).toContainText("TEST-REQ-GET");
    await expect(reachable).toContainText("Reached at app/client.py:5.");
    await expect(reachable).toContainText("Static reachability is evidence of use, not of exploitability.");
    for (const item of await indicators.all()) expect(await item.locator("ul li").count()).toBeGreaterThan(0);
    await expect(page.getByTestId("indicators")).toContainText("An indicator is not a prediction of a specific vulnerability or attack");
  });

  test("evidence is labelled observed, derived, predicted or recommended", async ({ page }) => {
    await open(page, intelligenceState());
    await row(page, "requests").getByRole("button", { name: "Show evidence for requests" }).click();
    const evidence = page.getByTestId("risk-evidence");
    await expect(evidence.getByTestId("evidence-observed")).toContainText("OBSERVED");
    await expect(evidence.getByTestId("evidence-observed")).toContainText("Installed version: 2.19.1.");
    await expect(evidence.getByTestId("evidence-observed")).toContainText("GHSA-x84v-xcm2-53pg");
    await expect(evidence.getByTestId("evidence-derived")).toContainText("Exposure classification: DIRECT_VULNERABILITY.");
    await expect(evidence.getByTestId("evidence-predicted")).toContainText("Predictive dependency risk 45.2 of 100 (MEDIUM)");
    await expect(evidence.getByTestId("evidence-predicted")).toContainText("Not a forecast of a specific event");
    await expect(evidence.getByTestId("evidence-recommended")).toContainText("Review the changes between 2.19.1 and 2.32.3 before planning an update.");
    await expect(evidence.getByTestId("evidence-recommended")).toContainText("Nothing is changed automatically");
    await expect(page.getByTestId("dependency-detail")).not.toContainText(OVERCLAIMS);
  });

  test("values the registry did not provide are shown as unknown, never as zero", async ({ page }) => {
    await open(page, intelligenceState());
    await row(page, "ms").getByRole("button", { name: "Show evidence for ms" }).click();
    const health = page.getByTestId("health-card");
    await expect(health.getByTestId("version-position")).toContainText("Not compared: release metadata is not available");
    await expect(health.getByTestId("metadata-confidence")).toHaveText("NONE");
    for (const field of ["latest_release", "latest_release_at", "release_age_days", "release_frequency", "reachable_vulnerability_count"]) {
      await expect(health.locator(`[data-field="${field}"] dd`)).toHaveText("Unknown");
    }
    await expect(health.locator('[data-field="known_vulnerability_count"] dd')).toHaveText("1");
    await expect(health.getByTestId("metadata-source")).toContainText("npm · not found");
    await health.getByText(/Why \d+ values are unknown/).click();
    await expect(health.getByTestId("health-unknown")).toContainText("No registry metadata is available for this package (NOT_FOUND).");

    const fragility = page.getByTestId("fragility-score");
    for (const factor of ["version_lag", "release_staleness"]) {
      const line = fragility.locator(`[data-factor="${factor}"]`);
      await expect(line).toHaveAttribute("data-status", "UNKNOWN");
      await expect(line.locator("td:nth-child(3)")).toHaveText("unknown");
      await expect(line.locator("td:nth-child(4)")).toHaveText("—");
    }
    await expect(fragility).toContainText("confidence 70%");
    await expect(fragility.getByTestId("fragility-score-unknown")).toContainText("2 factors have no data and add nothing");
    await expect(page.locator('[data-testid="indicator"][data-type="INSUFFICIENT_METADATA"]')).toContainText("are not estimated");
  });

  test("a registry answer without release dates gives versions but no invented dates", async ({ page }) => {
    await open(page, intelligenceState());
    await row(page, "debug").getByRole("button", { name: "Show evidence for debug" }).click();
    const health = page.getByTestId("health-card");
    await expect(health.locator('[data-field="latest_release"] dd')).toHaveText("4.3.4");
    for (const field of ["latest_release_at", "installed_release_at", "release_age_days", "release_frequency"]) {
      await expect(health.locator(`[data-field="${field}"] dd`)).toHaveText("Unknown");
    }
    await expect(health.locator('[data-field="reachable_vulnerability_count"] dd')).toHaveText("0");     // no known vulnerability: zero is a fact
    await expect(health.getByTestId("metadata-source")).toContainText("versions only, no release dates");
    await expect(page.getByTestId("dependency-graph-risk").getByTestId("exposure-sources")).toContainText("ms@2.0.0 · 1 step away");
    await expect(page.getByTestId("dependency-graph-risk")).toContainText("No advisory matches this package");
  });

  test("filters and sorting are sent to the server and narrow the table", async ({ page }) => {
    const state = intelligenceState();
    await open(page, state);
    await page.getByLabel("Indicator").selectOption("OUTDATED_DEPENDENCY");
    await expect(page.getByTestId("risk-row")).toHaveCount(3);
    await expect(page.getByTestId("risk-range")).toHaveText("1–3 of 3 (filtered from 9)");
    expect(state.requests.some((r) => r.path.endsWith("/predictive-risk") && r.query.indicator === "OUTDATED_DEPENDENCY")).toBe(true);
    await page.getByLabel("Indicator").selectOption("");

    await page.getByLabel("Known vulnerabilities only").check();
    await expect(page.getByTestId("risk-row")).toHaveCount(4);
    await page.getByLabel("Relationship").selectOption("TRANSITIVE");
    expect(await page.getByTestId("risk-row").evaluateAll((rows) => rows.map((r) => r.getAttribute("data-name")))).toEqual(["qs", "ms"]);
    await page.getByLabel("Known vulnerabilities only").uncheck();
    await page.getByLabel("Relationship").selectOption("");

    await page.getByLabel("Predictive risk", { exact: true }).selectOption("MEDIUM");
    await expect(page.getByTestId("risk-row")).toHaveCount(1);
    await page.getByLabel("Predictive risk", { exact: true }).selectOption("HIGH");
    await expect(page.getByTestId("no-rows")).toContainText("No dependencies match these filters");
    await page.getByLabel("Predictive risk", { exact: true }).selectOption("");

    await page.getByLabel("Search by package").fill("body");
    await expect(page.getByTestId("risk-row")).toHaveCount(1);
    await expect(row(page, "body-parser")).toBeVisible();
    await page.getByLabel("Search by package").fill("");
    await expect(page.getByTestId("risk-row")).toHaveCount(9);

    await page.getByLabel("Sort by").selectOption("fragility");
    await expect(page.getByTestId("risk-row").first()).toHaveAttribute("data-name", "debug");
    expect(state.requests.some((r) => r.query.sort === "fragility")).toBe(true);
  });

  test("a failed list request is reported and can be retried", async ({ page }) => {
    const state = intelligenceState({ failures: { "/predictive-risk": 500 } });
    await open(page, state);
    await expect(page.getByRole("alert")).toContainText("Internal server error");
    await expect(page.getByTestId("risk-table")).toHaveCount(0);
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("risk-row")).toHaveCount(9);
  });

  test("a failed evidence request is reported in the row and can be retried", async ({ page }) => {
    const state = intelligenceState({ failures: { [`/predictive-risk/${idOf("requests")}`]: 500 } });
    await open(page, state);
    await row(page, "requests").getByRole("button", { name: "Show evidence for requests" }).click();
    await expect(page.getByTestId("risk-table").getByRole("alert")).toContainText("Internal server error");
    state.failures = {};
    await page.getByTestId("risk-table").getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("predictive-score-value")).toHaveText("45.2");
    await expect(row(page, "requests").getByRole("button", { name: "Hide evidence for requests" })).toBeVisible();
  });

  test("a failed analysis says so and keeps the earlier results marked as earlier", async ({ page }) => {
    await open(page, intelligenceState({ jobs: [makeIntelligenceJob("failed", {
      message: "Failed", error: { code: "GRAPH_TOO_LARGE", message: "The dependency graph has 6200 packages; the limit is 5000." } })] }));
    const job = page.getByTestId("intelligence-job");
    await expect(job.getByText("Failed", { exact: true })).toBeVisible();
    await expect(job.getByRole("alert")).toContainText("The analysis failed. Results below, if any, are from an earlier run.");
    await expect(job.getByRole("alert")).toContainText("The dependency graph has 6200 packages; the limit is 5000.");
    await expect(job.getByRole("alert")).toContainText("GRAPH_TOO_LARGE");
    await expect(page.getByTestId("risk-row")).toHaveCount(9);
  });

  test("a partial analysis is not presented as complete", async ({ page }) => {
    const list = clone(predictive.list);
    Object.assign(list.analysis.summary.metadata, { errors: 1, incomplete: true });
    await open(page, intelligenceState({ list, jobs: [makeIntelligenceJob("partial")] }));
    const job = page.getByTestId("intelligence-job");
    await expect(job.getByText("Partial", { exact: true })).toBeVisible();
    await expect(job.getByText("Completed")).toHaveCount(0);
    const notice = job.getByTestId("job-partial");
    await expect(notice).toContainText("The analysis finished with part of its input missing");
    await expect(notice).toContainText("Release metadata could not be collected for 1 of 9 package(s)");
    await expect(notice).toContainText("unknown, not estimated");
    await expect(notice).toContainText("METADATA_INCOMPLETE");
    await expect(page.getByTestId("metadata-incomplete")).toContainText("Release metadata could not be collected for 1 of 9 packages");
    await expect(page.getByTestId("risk-row")).toHaveCount(9);                         // what was analysed is still shown
    await expect(job.getByRole("button", { name: "Analyse again" })).toBeEnabled();
  });

  test("the start button is disabled while another job runs, and refusals are explained", async ({ page }) => {
    const busy = intelligenceState({ otherActive: { id: "other", type: "vulnerability_sync", state: "running" } });
    await open(page, busy);
    await expect(page.getByTestId("intelligence-job")).toContainText("A vulnerability check is in progress for this project. Only one job runs at a time.");
    await expect(page.getByRole("button", { name: "Analyse again" })).toBeDisabled();

    const limited = intelligenceState({ startStatus: 429 });
    await open(page, limited);
    await page.getByRole("button", { name: "Analyse again" }).click();
    await expect(page.getByTestId("intelligence-job").getByRole("alert")).toContainText("Too many jobs requested");
  });

  test("results older than the latest vulnerability check or reachability analysis are flagged", async ({ page }) => {
    await open(page, intelligenceState());
    await expect(page.getByTestId("risk-row")).toHaveCount(9);
    await expect(page.getByTestId("stale-warning")).toHaveCount(0);
    await open(page, intelligenceState({ currentInputs: { vulnerability_scan_matched_at: "2027-01-01T00:00:00Z", reachability_completed_at: null } }));
    await expect(page.getByTestId("stale-warning")).toContainText("Analyse again to take the newer findings into account");
  });

  test("when only fragility was analysed, the other layers say 'Not analysed' instead of showing zero", async ({ page }) => {
    await open(page, fragilityOnlyState());
    await expect(page.getByTestId("risk-table")).toHaveAttribute("data-mode", "fragility");
    await expect(page.getByTestId("risk-row")).toHaveCount(9);
    const first = page.getByTestId("risk-row").first();
    await expect(first).toHaveAttribute("data-name", "debug");
    await expect(first.getByTestId("cell-fragility")).toContainText("44.9");
    for (const cell of ["cell-predictive", "cell-exposure", "cell-reachability", "cell-indicators"]) await expect(first.getByTestId(cell)).toHaveText("Not analysed");
    const overview = page.getByTestId("fragility-overview");
    for (const label of ["Highest predictive risk", "Known-vulnerable packages", "Indicators"]) {
      await expect(overview.locator("div.card", { hasText: label }).first()).toContainText("Not analysed");
    }
    await expect(overview.locator("div.card", { hasText: "Highest fragility" }).first()).toContainText("44.9");
    await expect(page.getByTestId("no-scan-note")).toContainText("vulnerability counts are unknown and exposure was not traced");
    await expect(page.getByTestId("model-versions")).toHaveText("fragility-v1");
    await expect(page.getByTestId("graph-risk-panel")).toHaveCount(0);

    await first.getByRole("button", { name: "Show evidence for debug" }).click();
    await expect(page.getByTestId("predictive-not-analysed")).toContainText("Analysis not available");
    await expect(page.getByTestId("fragility-score-value")).toHaveText("44.9");
    await expect(page.getByTestId("health-card").locator('[data-field="known_vulnerability_count"] dd')).toHaveText("Unknown");
    await expect(page.getByTestId("indicators")).toHaveCount(0);

    await page.getByRole("tab", { name: "Risk graph" }).click();
    await expect(page.getByTestId("graph-not-available")).toContainText("Analysis not available");
    await expect(page.getByTestId("risk-graph")).toHaveCount(0);
  });

  test("changes since the previous analysis are listed from the stored history", async ({ page }) => {
    await open(page, intelligenceState());
    const changes = page.getByTestId("analysis-changes");
    await expect(changes.getByTestId("changes-summary")).toContainText("(same commit): 1 changed · 0 added · 0 removed · 8 unchanged.");
    const item = changes.getByTestId("changes-list").locator("li");
    await expect(item).toHaveCount(1);
    await expect(item).toContainText("requests");
    await expect(item).toContainText("predictive risk +5.0");
    await expect(item).toContainText("new indicator: Reachable vulnerable dependency");
    await expect(changes).toContainText("2 analyses of this kind are stored for this project.");

    await open(page, intelligenceState({ history: { items: [clone(predictive.history.items[0])] } }));
    await expect(page.getByTestId("no-previous-analysis")).toContainText("This is the only stored analysis of this kind");
  });
});

test.describe("risk graph", () => {
  async function openGraph(page: Page, state = intelligenceState()) {
    await open(page, state);
    await page.getByRole("tab", { name: "Risk graph" }).click();
    await expect(page.getByTestId("risk-graph")).toBeVisible();
    return state;
  }
  const nodes = (page: Page) => page.getByTestId("risk-node");
  const names = async (page: Page) => (await nodes(page).evaluateAll((items) => items.map((n) => n.getAttribute("data-node")))).sort();

  test("draws exactly the analysed packages and dependency edges", async ({ page }) => {
    const state = await openGraph(page);
    await expect(nodes(page)).toHaveCount(9);
    await expect(page.getByTestId("risk-graph-root")).toContainText("octo/intelligence-demo");
    expect(await names(page)).toEqual(predictive.graph.nodes.map((n: { normalized_name: string }) => n.normalized_name).sort());
    await expect(page.getByTestId("risk-graph-summary")).toHaveText("Showing 9 of 9 packages and 12 of 12 edges");
    await expect(page.locator(".react-flow__edge")).toHaveCount(12);
    // Edges that lead to a package with a known vulnerability, or to one that depends on such a package, are marked.
    await expect(page.locator(".react-flow__edge.exposure-edge")).toHaveCount(11);
    await expect(page.locator(".react-flow__edge.plain-edge")).toHaveCount(1);            // project → PyYAML
    expect(state.requests.filter((r) => r.path.endsWith("/predictive-risk/graph"))).toHaveLength(1);
    await expect(page.getByTestId("risk-graph-legend")).toContainText("Only packages and dependency edges found in the repository are drawn.");
  });

  test("nodes carry their scores, level and exposure as text", async ({ page }) => {
    await openGraph(page);
    const requests = page.locator('[data-testid="risk-node"][data-node="requests"]');
    await expect(requests).toHaveAttribute("data-level", "MEDIUM");
    await expect(requests).toHaveAttribute("data-classification", "DIRECT_VULNERABILITY");
    for (const text of ["requests", "2.19.1", "risk 45.2", "fragility 13.8", "direct · known vulnerability · reachable"]) await expect(requests).toContainText(text);
    const debug = page.locator('[data-testid="risk-node"][data-node="debug"]');
    await expect(debug).toHaveAttribute("data-level", "LOW");
    await expect(debug).toContainText("transitive · requires vulnerable");
    await expect(debug).not.toContainText("known vulnerability");
    await expect(page.locator('[data-testid="risk-node"][data-node="pyyaml"]')).toContainText(/^PyYAML5\.1risk 0\.0fragility 0\.0direct$/);
  });

  test("filters narrow the graph without inventing or reconnecting anything", async ({ page }) => {
    await openGraph(page);
    const filters = page.getByTestId("graph-filters");
    await filters.getByLabel("Vulnerable").check();
    expect(await names(page)).toEqual(["lodash", "ms", "qs", "requests"]);
    await expect(page.getByTestId("risk-graph-summary")).toHaveText("Showing 4 of 9 packages and 2 of 12 edges");   // only the two direct ones keep an edge
    await filters.getByLabel("Reachable").check();
    expect(await names(page)).toEqual(["requests"]);
    await filters.getByLabel("Vulnerable").uncheck();
    await filters.getByLabel("Reachable").uncheck();

    await filters.getByLabel("High centrality").check();
    expect(await names(page)).toEqual(["debug"]);
    await filters.getByLabel("High centrality").uncheck();

    await filters.getByLabel("Relationship").selectOption("DIRECT");
    expect(await names(page)).toEqual(["express", "lodash", "morgan", "pyyaml", "requests"]);
    await filters.getByLabel("Relationship").selectOption("TRANSITIVE");
    expect(await names(page)).toEqual(["body-parser", "debug", "ms", "qs"]);
    await filters.getByLabel("Relationship").selectOption("");

    await filters.getByLabel("Predictive risk").selectOption("MEDIUM");
    expect(await names(page)).toEqual(["requests"]);
    await filters.getByLabel("Predictive risk").selectOption("");
    await filters.getByLabel("Fragility").selectOption("MEDIUM");
    expect(await names(page)).toEqual(["debug"]);
    await filters.getByLabel("Fragility").selectOption("HIGH");
    await expect(page.getByTestId("graph-no-match")).toContainText("No packages match these filters.");
    await expect(page.getByTestId("risk-graph-summary")).toHaveText("Showing 0 of 9 packages and 0 of 12 edges");
    await filters.getByLabel("Fragility").selectOption("");

    await filters.getByLabel("Search by package").fill("qs");
    expect(await names(page)).toEqual(["qs"]);
  });

  test("selecting a package shows its scores and evidence beside the graph", async ({ page }) => {
    const state = await openGraph(page);
    const aside = page.getByTestId("risk-graph-details");
    await expect(aside).toContainText("Select a package in the graph");
    await page.locator('[data-testid="risk-node"][data-node="qs"]').click();
    await expect(aside).toContainText("qs@6.7.0");
    await expect(aside).toContainText("transitive · depth 2");
    await expect(aside.getByTestId("predictive-score-value")).toHaveText("33.7");
    // The source publishes no severity and npm is not analysed for reachability: both factors are shown as assumed, not measured.
    for (const factor of ["vulnerability_exposure", "reachability"]) {
      await expect(aside.getByTestId("predictive-score").locator(`[data-factor="${factor}"]`)).toHaveAttribute("data-status", "ASSUMED");
      await expect(aside.getByTestId("predictive-score").locator(`[data-factor="${factor}"] td:nth-child(3)`)).toContainText("assumed");
    }
    await expect(aside.getByTestId("predictive-score-assumed")).toContainText("2 factors use the model's neutral value because the fact is not established");
    await expect(aside.locator('[data-testid="indicator"][data-type="VULNERABILITY_CLUSTER"]')).toContainText("3 distinct known vulnerabilities match the installed version 6.7.0.");
    await expect(aside.getByTestId("risk-evidence")).toBeVisible();
    expect(state.requests.filter((r) => r.path.endsWith(`/predictive-risk/${idOf("qs")}`))).toHaveLength(1);
    await aside.getByRole("button", { name: "Close details" }).click();
    await expect(aside).toContainText("Select a package in the graph");
  });

  test("a graph that cannot be loaded is reported and can be retried", async ({ page }) => {
    const state = intelligenceState({ failures: { "/predictive-risk/graph": 500 } });
    await open(page, state);
    await page.getByRole("tab", { name: "Risk graph" }).click();
    await expect(page.getByTestId("project-content").getByRole("alert")).toContainText("Internal server error");
    await expect(page.getByTestId("risk-graph")).toHaveCount(0);
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(nodes(page)).toHaveCount(9);
  });
});
