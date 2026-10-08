import { expect, test } from "@playwright/test";

import { defaultState, mockApi, projectUrl } from "./mock-api";
import { findings, makeAnalysis, makeReachabilityJob, mockReachability, reachabilityState } from "./mock-reachability";
import type { ReachabilityState } from "./mock-reachability";

async function open(page: import("@playwright/test").Page, state: ReachabilityState) {
  await mockApi(page, defaultState({ analysed: state.analysed }));
  await mockReachability(page, state);
  await page.goto(projectUrl("/reachability"));
}

test.describe("code reachability page", () => {
  test("a project without a dependency inventory is sent to the analysis first", async ({ page }) => {
    await open(page, reachabilityState({ analysed: false, scanned: false, analysis: null, jobs: [null] }));
    await expect(page.getByTestId("not-analysed")).toBeVisible();
    await expect(page.getByTestId("reachability-table")).toHaveCount(0);
  });

  test("without a vulnerability check the analysis cannot be started and the reason is given", async ({ page }) => {
    await open(page, reachabilityState({ scanned: false, analysis: null, jobs: [null] }));
    await expect(page.getByTestId("needs-scan")).toContainText("Run a vulnerability check first");
    await expect(page.getByRole("button", { name: "Start analysis" })).toBeDisabled();
    await page.getByTestId("needs-scan").getByRole("link", { name: "Go to vulnerabilities" }).click();
    await expect(page).toHaveURL(/\/vulnerabilities$/);
  });

  test("before any analysis nothing is shown and its absence is not presented as unreachable", async ({ page }) => {
    await open(page, reachabilityState({ analysis: null, jobs: [null] }));
    const job = page.getByTestId("reachability-job");
    await expect(job.getByText("Not run")).toBeVisible();
    await expect(job.getByRole("button", { name: "Start analysis" })).toBeEnabled();
    await expect(job).toContainText("without running it");
    await expect(page.getByTestId("not-analysed")).toContainText("has not been found unreachable; it has not been analysed");
    await expect(page.getByTestId("reachability-stats")).toHaveCount(0);
    await expect(page.getByTestId("project-content")).not.toContainText(/GHSA-|TEST-REQ|trust score|risk score|exploitable/i);
  });

  test("starting an analysis shows queued, progress and then the findings", async ({ page }) => {
    const state = reachabilityState({
      analysis: null, findings: [], jobs: [null],
      startJobs: [makeReachabilityJob("queued"), makeReachabilityJob("running"), makeReachabilityJob("completed")],
      afterAnalysis: { analysis: makeAnalysis(), findings },
    });
    await open(page, state);
    const job = page.getByTestId("reachability-job");
    await job.getByRole("button", { name: "Start analysis" }).click();
    await expect(job.getByText("Queued")).toBeVisible();
    await expect(job.getByText("Read and parsed 25 of 38 source file(s)")).toBeVisible();
    await expect(job.getByRole("button", { name: "Analysis in progress" })).toBeDisabled();
    for (const stage of ["List source", "Parse", "Build graph", "Map symbols", "Search paths"]) await expect(job.getByText(stage, { exact: true })).toBeVisible();
    await expect(job.getByText("Completed")).toBeVisible({ timeout: 15000 });
    await expect(job).toContainText("4 finding(s) analysed: 1 reachable, 1 not confirmed, 1 unknown, 1 unsupported");
    await expect(page.getByTestId("reachability-table").locator("tbody tr")).toHaveCount(4);
    expect(state.requests.filter((r) => r.method === "POST" && r.path.endsWith("/code-reachability/analyze"))).toHaveLength(1);
  });

  test("summary counts each status and says what the analysis covered", async ({ page }) => {
    await open(page, reachabilityState());
    const stats = page.getByTestId("reachability-stats");
    for (const [label, value] of [["Reachable", "1"], ["Not confirmed", "1"], ["Unknown", "1"], ["Unsupported", "1"], ["Source files", "38 / 38"]]) {
      await expect(stats.locator("div.card", { hasText: label }).first()).toContainText(value);
    }
    const notes = page.getByTestId("coverage-notes");
    await expect(notes).toContainText("2 of 4 findings name the affected functions");
    await expect(notes).toContainText("Source in other languages is not analysed (JavaScript: 61 files)");
    await expect(notes).toContainText("71 calls or references could not be bound statically");
    await expect(page.getByTestId("project-content")).toContainText("58 functions · 207 edges · 71 unresolved uses");
    await expect(page.getByTestId("incomplete-source")).toHaveCount(0);
  });

  test("the table lists dependency, version, vulnerability, status, confidence and source location", async ({ page }) => {
    await open(page, reachabilityState());
    const rows = page.getByTestId("reachability-table").locator("tbody tr");
    const reachable = rows.nth(0);
    for (const text of ["requests", "PyPI", "direct", "2.19.1", "TEST-REQ-GET", "High", "Reachable", "A path to the affected functionality was found", "HIGH", "app/client.py:5"]) {
      await expect(reachable).toContainText(text);
    }
    await expect(rows.nth(1)).toContainText("Unknown");
    await expect(rows.nth(1)).toContainText("The advisory does not say which functions are affected");
    await expect(rows.nth(1)).toContainText("CVE-2018-18074");
    await expect(rows.nth(2)).toContainText("Not confirmed");
    await expect(rows.nth(2)).toContainText("MEDIUM");
    await expect(rows.nth(3)).toContainText("Unsupported");
    await expect(rows.nth(3)).toContainText("This ecosystem's source is not analysed");
    await expect(rows.nth(3).locator("td").nth(6)).toHaveText("—");       // no confidence where nothing was concluded
    await expect(page.getByTestId("reachability-range")).toHaveText("1–4 of 4");
  });

  test("opening a reachable finding shows the path, each step's source line and the evidence", async ({ page }) => {
    await open(page, reachabilityState());
    await page.getByRole("button", { name: "Show evidence for requests TEST-REQ-GET" }).click();
    const evidence = page.getByTestId("reachability-evidence");
    await expect(evidence).toContainText("does not show that the vulnerability can be exploited");
    await expect(evidence).toContainText("Observed · path to the affected functionality");
    const graph = evidence.getByTestId("path-graph");
    await expect(graph.getByTestId("path-node")).toHaveCount(3);
    await expect(graph.locator('[data-kind="external"]')).toContainText("requests.get");
    const steps = evidence.getByTestId("path-steps").locator("li");
    await expect(steps).toHaveCount(2);
    await expect(steps.nth(0)).toContainText("app.main:handle_request");
    await expect(steps.nth(0)).toContainText("return fetch(url)");
    await expect(steps.nth(1)).toContainText("return requests.get(url)");
    await expect(steps.nth(1)).toContainText("call to an explicitly imported name");
    const link = steps.nth(1).getByRole("link", { name: "app/client.py:5" });
    await expect(link).toHaveAttribute("href", /\/blob\/4c8057c3bbed0e55f916341187cf4f2d3ddaaea6\/app\/client\.py#L5$/);
    await expect(link).toHaveAttribute("rel", "noopener noreferrer");
    await expect(evidence).toContainText("2 steps · starts at code that nothing else in the analysed source calls (a possible entry point)");
    await expect(evidence.getByTestId("import-sites")).toContainText("import requests");
    await expect(evidence).toContainText("Published in the advisory record.");
    await expect(evidence).toContainText("the affected name itself");
    await expect(evidence).toContainText("It is not a likelihood of exploitation.");
    await expect(evidence.getByTestId("inference-notes")).toContainText("mapped to the dependency by name");
    await expect(evidence).toContainText("analyzer 4.0.0");
  });

  test("an unknown finding says the affected functions are not published and shows only package usage", async ({ page }) => {
    await open(page, reachabilityState());
    await page.getByRole("button", { name: "Show evidence for requests GHSA-x84v-xcm2-53pg" }).click();
    const evidence = page.getByTestId("reachability-evidence");
    await expect(evidence.getByTestId("symbol-mapping-unknown")).toContainText("SYMBOL_MAPPING_UNKNOWN");
    await expect(evidence.getByTestId("symbol-mapping-unknown")).toContainText("None is assumed");
    await expect(evidence).toContainText("Observed · path to the package (not to a known affected function)");
    await expect(evidence).toContainText("Nothing was concluded, so no confidence applies.");
    await expect(evidence).toContainText("Application code calls into this package");
  });

  test("not confirmed and unsupported findings show no path and make no safety claim", async ({ page }) => {
    await open(page, reachabilityState());
    await page.getByRole("button", { name: "Show evidence for PyYAML TEST-YAML-LOAD" }).click();
    const evidence = page.getByTestId("reachability-evidence");
    await expect(evidence).toContainText("This is not a statement that the application is safe.");
    await expect(evidence.getByTestId("path-graph")).toHaveCount(0);
    await expect(evidence).toContainText("yaml.safe_load");
    await page.getByRole("button", { name: "Hide evidence for PyYAML TEST-YAML-LOAD" }).click();
    await page.getByRole("button", { name: "Show evidence for xlsx GHSA-4r6h-8v6p-xvw6" }).click();
    await expect(page.getByTestId("reachability-evidence")).toContainText("Not analysed for this ecosystem.");
    await expect(page.getByTestId("reachability-evidence")).toContainText("nothing is concluded");
  });

  test("a failure loading one finding's evidence is shown in place and can be retried", async ({ page }) => {
    const state = reachabilityState({ failures: { "/code-reachability/f1": 500 } });
    await open(page, state);
    await page.getByRole("button", { name: "Show evidence for requests TEST-REQ-GET" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Internal server error" })).toBeVisible();
    await expect(page.getByTestId("reachability-table").locator("tbody tr").first()).toBeVisible();
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("reachability-evidence")).toBeVisible();
  });

  test("status filter and search are sent to the server", async ({ page }) => {
    const state = reachabilityState();
    await open(page, state);
    await page.getByLabel("Reachability", { exact: true }).selectOption("UNKNOWN");
    await expect(page.getByTestId("reachability-table").locator("tbody tr")).toHaveCount(1);
    await expect(page.getByTestId("reachability-range")).toHaveText("1–1 of 1 (filtered from 4)");
    expect(state.requests.some((r) => r.path.endsWith("/code-reachability") && r.query.status === "UNKNOWN")).toBe(true);
    await page.getByLabel("Reachability", { exact: true }).selectOption("");
    await page.getByLabel("Search by package or identifier").fill("pyyaml");
    await expect(page.getByTestId("reachability-table").locator("tbody tr")).toHaveCount(1);
    expect(state.requests.some((r) => r.query.q === "pyyaml")).toBe(true);
    await page.getByLabel("Search by package or identifier").fill("nothing-matches");
    await expect(page.getByTestId("no-findings")).toContainText("No findings match these filters");
  });

  test("an analysis with nothing to trace says so", async ({ page }) => {
    await open(page, reachabilityState({ findings: [], analysis: makeAnalysis([]) }));
    await expect(page.getByTestId("no-findings")).toContainText("No vulnerable dependencies to analyse");
    await expect(page.getByTestId("no-findings")).toContainText("there was nothing to trace");
  });

  test("incompletely analysed source is stated with its consequence", async ({ page }) => {
    await open(page, reachabilityState({ analysis: makeAnalysis(findings, {
      source_complete: false, incomplete_reasons: [{ reason: "SYNTAX_ERROR", files: 2 }, { reason: "SKIPPED_TOO_LARGE", files: 1 }] }) }));
    const note = page.getByTestId("incomplete-source");
    await expect(note).toContainText("2 files could not be parsed; 1 file were larger than the per-file limit");
    await expect(note).toContainText("the result is Unknown rather than Not confirmed");
  });

  test("a newer vulnerability check marks the analysis as out of date", async ({ page }) => {
    await open(page, reachabilityState({ scanMatchedAt: "2026-02-04T08:00:00Z" }));
    await expect(page.getByTestId("stale-warning")).toContainText("Analyse again to cover the current findings");
    await expect(page.getByRole("button", { name: "Analyse again" })).toBeEnabled();
  });

  test("a failed analysis shows the reason and code, and keeps earlier findings labelled as such", async ({ page }) => {
    await open(page, reachabilityState({ jobs: [makeReachabilityJob("failed", {
      message: "GitHub's rate limit was reached.", error: { code: "RATE_LIMITED", message: "GitHub's rate limit was reached. It resets at 12:00 UTC." } })] }));
    const job = page.getByTestId("reachability-job");
    await expect(job.getByText("Failed", { exact: true })).toBeVisible();
    await expect(job).toContainText("GitHub's rate limit was reached. It resets at 12:00 UTC.");
    await expect(job).toContainText("RATE_LIMITED");
    await expect(job).toContainText("Findings below, if any, are from an earlier run.");
    await expect(page.getByTestId("reachability-table")).toBeVisible();
  });

  test("while another job runs on the project, an analysis cannot be started", async ({ page }) => {
    await open(page, reachabilityState({ otherActive: { ...makeReachabilityJob("running"), id: "other", type: "vulnerability_sync" } }));
    const job = page.getByTestId("reachability-job");
    await expect(job.getByRole("button", { name: "Analyse again" })).toBeDisabled();
    await expect(job).toContainText("A vulnerability check is in progress for this project. Only one job runs at a time.");
  });

  test("a refused start is explained", async ({ page }) => {
    await open(page, reachabilityState({ startStatus: 429 }));
    await page.getByRole("button", { name: "Analyse again" }).click();
    await expect(page.getByTestId("reachability-job").getByRole("alert")).toContainText("Too many jobs requested");
  });

  test("a server error loading the page is shown with a retry", async ({ page }) => {
    const state = reachabilityState({ failures: { "/code-reachability": 500 } });
    await open(page, state);
    await expect(page.getByRole("alert").filter({ hasText: "Internal server error" })).toBeVisible();
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("reachability-table")).toBeVisible();
  });

  test("the page states that reachability is not exploitability and shows no scores", async ({ page }) => {
    await open(page, reachabilityState());
    const content = page.getByTestId("project-content");
    await expect(page.getByTestId("reachability-meaning")).toContainText("Static reachability is not exploitability.");
    await expect(page.getByTestId("reachability-meaning")).toContainText('"Not confirmed" and "Unknown" do not mean safe');
    await page.getByRole("button", { name: "Show evidence for requests TEST-REQ-GET" }).click();
    await expect(page.getByTestId("reachability-evidence")).toBeVisible();
    await expect(content).not.toContainText(/\bexploitable\b|risk score|trust score|\bsafe to\b|% likely/i);
  });

  test("the tab leads to the page", async ({ page }) => {
    await mockApi(page, defaultState());
    await mockReachability(page, reachabilityState());
    await page.goto(projectUrl());
    await page.getByRole("navigation", { name: "Project sections" }).getByRole("link", { name: "Code reachability" }).click();
    await expect(page).toHaveURL(/\/reachability$/);
    await expect(page.getByTestId("reachability-table")).toBeVisible();
  });
});
