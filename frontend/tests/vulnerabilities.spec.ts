import { expect, test } from "@playwright/test";

import { defaultState, makeJob, mockApi, projectUrl } from "./mock-api";
import { makeScan, makeSecurityJob, makeSync, matches, mockSecurity, securityState } from "./mock-security";
import type { SecurityState } from "./mock-security";

async function open(page: import("@playwright/test").Page, state: SecurityState) {
  await mockApi(page, defaultState({ analysed: state.analysed }));
  await mockSecurity(page, state);
  await page.goto(projectUrl("/vulnerabilities"));
}

test.describe("vulnerabilities page", () => {
  test("a project without a dependency inventory is sent to the analysis first", async ({ page }) => {
    await open(page, securityState({ analysed: false, scan: null, sync: null, vulnerabilityJobs: [null] }));
    await expect(page.getByTestId("not-analysed")).toBeVisible();
    await expect(page.getByTestId("vulnerability-table")).toHaveCount(0);
  });

  test("before any check, no findings are shown and their absence is not presented as a clean result", async ({ page }) => {
    await open(page, securityState({ scan: null, sync: null, vulnerabilityJobs: [null] }));
    const job = page.getByTestId("vulnerability-job");
    await expect(job.getByText("Not run")).toBeVisible();
    await expect(job.getByRole("button", { name: "Check for vulnerabilities" })).toBeEnabled();
    await expect(job.getByRole("button", { name: "Re-match stored advisories" })).toBeDisabled();
    const empty = page.getByTestId("not-scanned");
    await expect(empty).toContainText("No vulnerability check has been run for this snapshot");
    await expect(empty).toContainText("does not mean the dependencies are free of known vulnerabilities");
    await expect(page.getByTestId("vulnerability-stats")).toHaveCount(0);
    await expect(page.getByTestId("project-content")).not.toContainText(/CVE-\d|GHSA-|trust score|risk score/i);
  });

  test("running a check shows queued, progress and then the findings", async ({ page }) => {
    const state = securityState({
      scan: null, sync: null, matches: [],
      vulnerabilityJobs: [null, makeSecurityJob("vulnerability_sync", "queued"), makeSecurityJob("vulnerability_sync", "running"), makeSecurityJob("vulnerability_sync", "completed")],
      afterCheck: { scan: makeScan(), sync: makeSync(), matches },
    });
    await open(page, state);
    await page.getByRole("button", { name: "Check for vulnerabilities" }).click();
    const job = page.getByTestId("vulnerability-job");
    await expect(job.getByText("Queued")).toBeVisible();
    await expect(job.getByRole("button", { name: "Check in progress" })).toBeDisabled();
    await expect(page.getByTestId("vulnerability-table")).toHaveCount(0);                    // nothing claimed before completion
    await expect(job.getByText("Running")).toBeVisible();
    await expect(job.getByText("Fetching 3 advisory record(s)")).toBeVisible();
    await expect(job.getByText("Fetch advisories")).toBeVisible();
    await expect(job.getByText("Completed")).toBeVisible();
    await expect(page.getByTestId("vulnerability-table").locator("tbody tr")).toHaveCount(matches.length);
    await expect(job.getByRole("button", { name: "Check again" })).toBeEnabled();
    expect(state.requests.filter((r) => r.method === "POST" && r.path.endsWith("/vulnerabilities/sync"))).toHaveLength(1);
  });

  test("summary shows counts by published severity, the source and the snapshot", async ({ page }) => {
    await open(page, securityState());
    const stats = page.getByTestId("vulnerability-stats");
    for (const [label, value] of [["Affected versions", "2"], ["Vulnerabilities", "2"], ["Critical", "0"], ["High", "2"], ["Severity unknown", "1"]]) {
      await expect(stats.getByText(label, { exact: true }).locator("..")).toContainText(value);
    }
    await expect(stats).toContainText("of 10 dependency versions checked");
    await expect(stats).toContainText("3 advisory matches");
    await expect(page.getByText(/OSV · synchronised/)).toBeVisible();
    await expect(page.getByText("4c8057c3bb")).toBeVisible();
    const notes = page.getByTestId("coverage-notes");
    await expect(notes).toContainText("1 dependency has no resolved version and could not be checked");
    await expect(notes).toContainText("ecosystem the source does not cover (vcpkg)");
    await expect(notes).toContainText('1 advisory match could not be verified');
  });

  test("the table lists package, version, identifier, severity, source, range, fix and status", async ({ page }) => {
    await open(page, securityState());
    const table = page.getByTestId("vulnerability-table");
    const ghsa = table.getByRole("row", { name: /GHSA-x84v-xcm2-53pg/ }).first();
    for (const text of ["requests", "2.19.1", "CVE-2018-18074", "High", "osv", "< 2.20.0", "2.20.0", "Affected"]) await expect(ghsa).toContainText(text);
    const pysec = table.getByRole("row", { name: /PYSEC-2018-28/ });
    await expect(pysec.getByRole("cell").nth(4)).toHaveText("Unknown");                       // the source gives no severity
    const xlsx = table.getByRole("row", { name: /GHSA-4r6h-8v6p-xvw6/ });
    await expect(xlsx).toContainText("all versions (no fixed version published)");
    await expect(xlsx.getByRole("cell").nth(7)).toHaveText("none published");
    const guava = table.getByRole("row", { name: /guava/ });
    await expect(guava).toContainText("Not verified");
    await expect(guava.getByRole("cell").nth(6)).toHaveText("—");                             // no range is claimed for an unverified match
    await expect(page.getByTestId("vulnerability-range")).toHaveText("1–4 of 4");
  });

  test("opening a finding explains its source, what was observed, the match and the evidence", async ({ page }) => {
    await open(page, securityState());
    await page.getByRole("button", { name: "Show evidence for requests GHSA-x84v-xcm2-53pg" }).click();
    const evidence = page.getByTestId("match-evidence");
    await expect(evidence.getByText("Insufficiently Protected Credentials in Requests")).toBeVisible();
    await expect(evidence.getByRole("link", { name: /GHSA-x84v-xcm2-53pg/ })).toHaveAttribute("href", "https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg");
    await expect(evidence.getByRole("link", { name: "api/requirements.txt:1" })).toHaveAttribute("href", /github\.com\/octo\/demo\/blob\/4c8057c3.*\/api\/requirements\.txt#L1$/);
    await expect(evidence).toContainText("requests==2.19.1");
    await expect(evidence).toContainText("Version 2.19.1 is inside the affected range (< 2.20.0).");
    await expect(evidence).toContainText("not exploitability");
    await expect(evidence).toContainText("version_range_match");
    await expect(evidence).toContainText("introduced 0 → fixed 2.20.0");
    await expect(evidence).toContainText("base score 7.5 (computed from the vector)");
    await expect(evidence).toContainText("pep440");
    await page.getByRole("button", { name: "Hide evidence for requests GHSA-x84v-xcm2-53pg" }).click();
    await expect(evidence).toHaveCount(0);
  });

  test("an unverified finding says why it could not be decided", async ({ page }) => {
    await open(page, securityState());
    await page.getByRole("button", { name: /Show evidence for com.google.guava:guava/ }).click();
    const evidence = page.getByTestId("match-evidence");
    await expect(evidence).toContainText("The installed version cannot be ordered");
    await expect(evidence).toContainText("no conclusion is drawn");
    await expect(evidence.getByText("not determined")).toBeVisible();
  });

  test("a failure loading one finding's evidence is shown in place and can be retried", async ({ page }) => {
    const state = securityState({ failures: { "/vulnerabilities/m1": 500 } });
    await open(page, state);
    await page.getByRole("button", { name: "Show evidence for requests GHSA-x84v-xcm2-53pg" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Internal server error" })).toBeVisible();
    await expect(page.getByTestId("vulnerability-table").locator("tbody tr").first()).toBeVisible();   // the list stays usable
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("match-evidence")).toBeVisible();
  });

  test("filters and search are sent to the server", async ({ page }) => {
    const state = securityState();
    await open(page, state);
    const rows = page.getByTestId("vulnerability-table").locator("tbody tr");
    await page.getByLabel("Severity").selectOption("UNKNOWN");
    await expect(rows).toHaveCount(1);
    await expect(page.getByTestId("vulnerability-range")).toHaveText("1–1 of 1 (filtered from 4)");
    await page.getByLabel("Severity").selectOption("");
    await page.getByLabel("Status").selectOption("UNSUPPORTED");
    await expect(rows).toHaveCount(1);
    await page.getByLabel("Status").selectOption("");
    await page.getByLabel("Search by package or identifier").fill("CVE-2018-18074");
    await expect(rows).toHaveCount(2);
    await page.getByLabel("Search by package or identifier").fill("nothing-like-this");
    await expect(page.getByTestId("no-matches")).toContainText("No findings match these filters");
    const queries = state.requests.filter((r) => r.path.endsWith("/vulnerabilities")).map((r) => r.query);
    expect(queries.some((q) => q.severity === "UNKNOWN")).toBeTruthy();
    expect(queries.some((q) => q.match_status === "UNSUPPORTED")).toBeTruthy();
    expect(queries.some((q) => q.q === "CVE-2018-18074")).toBeTruthy();
  });

  test("a completed check with no affected versions says what that does and does not mean", async ({ page }) => {
    await open(page, securityState({ matches: [], scan: makeScan([]) }));
    const empty = page.getByTestId("no-matches");
    await expect(empty).toContainText("No known vulnerabilities matched");
    await expect(empty).toContainText("only the versions that could be checked");
    await expect(page.getByTestId("vulnerability-stats").getByText("Affected versions", { exact: true }).locator("..")).toContainText("0");
  });

  test("a failed check shows the reason and code, and keeps earlier findings labelled as such", async ({ page }) => {
    const failed = makeSecurityJob("vulnerability_sync", "failed", { message: "OSV returned HTTP 503.", error: { code: "PROVIDER_ERROR", message: "OSV returned HTTP 503." } });
    await open(page, securityState({ vulnerabilityJobs: [failed], sync: makeSync("failed") }));
    const job = page.getByTestId("vulnerability-job");
    await expect(job.getByText("Failed", { exact: true })).toBeVisible();
    await expect(job.getByRole("alert")).toContainText("The vulnerability check failed");
    await expect(job.getByRole("alert")).toContainText("OSV returned HTTP 503.");
    await expect(job.getByRole("alert")).toContainText("PROVIDER_ERROR");
    await expect(page.getByTestId("sync-warning")).toContainText("The last synchronisation failed");
    await expect(page.getByTestId("sync-warning")).toContainText("may be missing advisories");
    await expect(job.getByRole("button", { name: "Check again" })).toBeEnabled();
  });

  test("an incomplete synchronisation is flagged, never presented as complete", async ({ page }) => {
    await open(page, securityState({
      sync: makeSync("partial"),
      scan: makeScan(matches, { reported_but_not_stored_count: 1, reported_but_not_stored: [{ dependency: "maven:x@1", source_id: "GHSA-jfh8-c2jp-5v3q" }] }),
    }));
    await expect(page.getByTestId("sync-warning")).toContainText("The last synchronisation was incomplete");
    await expect(page.getByTestId("sync-warning")).toContainText("1 of 4 advisory record(s) could not be stored");
    await expect(page.getByTestId("coverage-notes")).toContainText("1 advisory record reported by the source could not be fetched");
  });

  test("a failed synchronisation with no earlier scan shows no findings", async ({ page }) => {
    await open(page, securityState({ scan: null, matches: [], sync: makeSync("failed"), vulnerabilityJobs: [makeSecurityJob("vulnerability_sync", "failed", { error: { code: "PROVIDER_TIMEOUT", message: "OSV did not respond in time." } })] }));
    await expect(page.getByTestId("sync-warning")).toContainText("No findings are shown until a check completes");
    await expect(page.getByTestId("not-scanned")).toBeVisible();
    await expect(page.getByTestId("vulnerability-table")).toHaveCount(0);
  });

  test("while another job runs on the project, a check cannot be started", async ({ page }) => {
    await open(page, securityState({ otherActive: { ...makeSecurityJob("sbom_generation", "running"), id: "other" } }));
    const job = page.getByTestId("vulnerability-job");
    await expect(job.getByText("An SBOM generation is in progress for this project")).toBeVisible();
    await expect(job.getByRole("button", { name: "Check again" })).toBeDisabled();
    await expect(job.getByRole("button", { name: "Re-match stored advisories" })).toBeDisabled();
  });

  test("a refused start is explained", async ({ page }) => {
    await open(page, securityState({ startStatus: 409 }));
    await page.getByRole("button", { name: "Check again" }).click();
    await expect(page.getByTestId("vulnerability-job").getByRole("alert")).toContainText("Another job is already queued or running for this project");
  });

  test("re-matching uses the stored advisories", async ({ page }) => {
    const state = securityState({ vulnerabilityJobs: [makeSecurityJob("vulnerability_sync", "completed"), makeSecurityJob("vulnerability_analysis", "completed", { message: "3 match(es) on 2 dependency version(s), using stored advisories" })] });
    await open(page, state);
    await page.getByRole("button", { name: "Re-match stored advisories" }).click();
    await expect(page.getByTestId("vulnerability-job")).toContainText("using stored advisories");
    expect(state.requests.filter((r) => r.method === "POST").map((r) => r.path.split("/").pop())).toEqual(["analyze"]);
  });

  test("a server error loading the page is shown with a retry", async ({ page }) => {
    const state = securityState({ failures: { "/vulnerabilities": 500 } });
    await open(page, state);
    await expect(page.getByRole("alert").filter({ hasText: "Internal server error" })).toBeVisible();
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("vulnerability-table")).toBeVisible();
  });

  test("no exploitability, risk or trust figures are shown", async ({ page }) => {
    await open(page, securityState());
    await page.getByRole("button", { name: "Show evidence for requests GHSA-x84v-xcm2-53pg" }).click();
    await expect(page.getByTestId("match-evidence")).toBeVisible();
    const content = page.getByTestId("project-content");
    await expect(content).not.toContainText(/trust score|risk score|exploit probab|EPSS|predicted|likelihood of/i);
    await expect(content).toContainText("It does not say that the vulnerable code is used or reachable");
  });

  test("the tabs lead to the new pages", async ({ page }) => {
    await mockApi(page, defaultState({ jobs: [makeJob("completed")] }));
    await mockSecurity(page, securityState());
    await page.goto(projectUrl());
    await page.getByRole("link", { name: "Vulnerabilities" }).click();
    await expect(page).toHaveURL(/\/vulnerabilities$/);
    await expect(page.getByTestId("vulnerability-table")).toBeVisible();
    await page.getByRole("link", { name: "SBOM", exact: true }).click();
    await expect(page).toHaveURL(/\/sbom$/);
    await expect(page.getByTestId("sbom-summary")).toBeVisible();
  });
});
