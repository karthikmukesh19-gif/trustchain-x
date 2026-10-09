import { expect, test } from "@playwright/test";

import { defaultState, makeJob, mockApi, projectUrl } from "./mock-api";

test.describe("analysis status on the project page", () => {
  test("a project that was never analysed shows no results and no invented figures", async ({ page }) => {
    await mockApi(page, defaultState({ analysed: false, jobs: [null] }));
    await page.goto(projectUrl());

    const status = page.getByTestId("analysis-status");
    await expect(status.getByText("Not run")).toBeVisible();
    await expect(status.getByRole("button", { name: "Run dependency analysis" })).toBeEnabled();
    await expect(page.getByRole("region", { name: "Repository snapshot" })).toHaveCount(0);
    await expect(page.getByRole("region", { name: "Dependencies" })).toHaveCount(0);
    // The trust score exists as a layer now; the page links to it and states that an unanalysed layer is unknown.
    const layers = page.getByTestId("layer-links");
    await expect(layers.getByRole("link", { name: "Trust score" })).toBeVisible();
    await expect(layers).toContainText("shows INSUFFICIENT DATA until enough has been analysed");
    await expect(layers).toContainText("is unknown, never a clean result");
    await expect(layers.getByText("Not scheduled · not built").first()).toBeVisible();
    await expect(layers).toContainText("Out of scope · static analysis only");
    await expect(page.locator("main")).not.toContainText(/CVE-|vulnerabilities found|risk score:/i);
  });

  test("running an analysis shows queued, then progress, then the results", async ({ page }) => {
    const state = defaultState({ analysed: false, jobs: [null, makeJob("queued"), makeJob("running"), makeJob("completed")] });
    await mockApi(page, state);
    await page.goto(projectUrl());

    await page.getByRole("button", { name: "Run dependency analysis" }).click();
    const status = page.getByTestId("analysis-status");
    await expect(status.getByText("Queued")).toBeVisible();
    await expect(status.getByRole("button", { name: "Analysis in progress" })).toBeDisabled();
    await expect(page.getByRole("region", { name: "Repository snapshot" })).toHaveCount(0);   // nothing claimed before completion

    await expect(status.getByText("Running")).toBeVisible();
    await expect(status.getByText("Reading 5 dependency file(s)")).toBeVisible();

    await expect(status.getByText("Completed")).toBeVisible();
    await expect(status.getByText("Analysis complete.")).toBeVisible();
    const snapshot = page.getByRole("region", { name: "Repository snapshot" });
    await expect(snapshot.getByText("4c8057c3bb")).toBeVisible();
    await expect(snapshot.getByText("main", { exact: true })).toBeVisible();
    await expect(status.getByRole("button", { name: "Run again" })).toBeEnabled();
    expect(state.requests.filter((r) => r.method === "POST" && r.path.endsWith("/analysis/dependencies"))).toHaveLength(1);
  });

  test("a failed analysis shows the reason and code, and stores nothing", async ({ page }) => {
    const failed = makeJob("failed", { message: "GitHub API rate limit reached. It resets at 12:00 UTC.",
      error: { code: "RATE_LIMITED", message: "GitHub API rate limit reached. It resets at 12:00 UTC. Set GITHUB_TOKEN to raise the limit from 60 to 5000 requests per hour.", retry_at: "2026-02-03T12:00:00Z" } });
    await mockApi(page, defaultState({ analysed: false, jobs: [failed] }));
    await page.goto(projectUrl());

    const alert = page.getByTestId("analysis-status").getByRole("alert");
    await expect(alert).toContainText("The analysis failed. No results were stored from this run.");
    await expect(alert).toContainText("Set GITHUB_TOKEN");
    await expect(alert).toContainText("RATE_LIMITED");
    await expect(page.getByRole("region", { name: "Repository snapshot" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Run again" })).toBeEnabled();
  });

  test("a rejected request is explained", async ({ page }) => {
    await mockApi(page, defaultState({ analysed: false, jobs: [null], startStatus: 409 }));
    await page.goto(projectUrl());
    await page.getByRole("button", { name: "Run dependency analysis" }).click();
    await expect(page.getByTestId("analysis-status").getByRole("alert")).toContainText("already queued or running");
  });

  test("a status that cannot be loaded is reported, not hidden", async ({ page }) => {
    await mockApi(page, defaultState({ analysed: false, jobs: [null], failures: { "/analysis/status": 500 } }));
    await page.goto(projectUrl());
    await expect(page.getByTestId("analysis-status").getByRole("alert")).toContainText("Internal server error");
  });

  test("completed results show snapshot, languages, package managers and dependency totals", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl());

    const languages = page.getByRole("region", { name: "Language detection" });
    await expect(languages).toContainText("Primary language: JavaScript");
    await expect(languages).toContainText("GitHub reports Python");
    await expect(languages).toContainText("71.0% · 38 files · high confidence");
    await languages.getByText("Evidence").first().click();
    await expect(languages.getByText("frontend/src/App.jsx")).toBeVisible();

    const managers = page.getByRole("region", { name: "Package managers" });
    await expect(managers).toContainText("web/package.json · web/package-lock.json");
    await expect(managers.getByText("Detected only")).toBeVisible();                       // bundler: recognised, not parsed
    await managers.getByRole("button", { name: "Show all 5 dependency files" }).click();
    await expect(managers.getByRole("row", { name: /Gemfile/ })).toContainText("Not supported");
    await expect(managers.getByRole("row", { name: /broken\/package\.json/ })).toContainText("Could not parse");
    await expect(managers.getByRole("row", { name: /broken\/package\.json/ })).toContainText("Not valid JSON");

    const dependencies = page.getByRole("region", { name: "Dependencies" });
    await expect(dependencies.getByText("Total").locator("..")).toContainText("6");
    await expect(dependencies.getByText("Unresolved versions").locator("..")).toContainText("1");
    await dependencies.getByRole("link", { name: "View dependencies" }).click();
    await expect(page).toHaveURL(new RegExp(`${projectUrl("/dependencies")}$`));
  });
});
