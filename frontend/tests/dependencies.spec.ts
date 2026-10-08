import { expect, test } from "@playwright/test";

import { defaultState, mockApi, nodes, projectUrl } from "./mock-api";

test.describe("dependencies page", () => {
  test("shows the totals, ecosystems, package managers, snapshot and analysis time", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/dependencies"));

    const stats = page.getByTestId("dependency-stats");
    for (const [label, value] of [["Total dependencies", "6"], ["Direct", "3"], ["Transitive", "2"], ["Unresolved versions", "1"],
      ["Dependency depth", "3"], ["Relationship unknown", "1"]]) {
      await expect(stats.getByText(label, { exact: true }).locator("..")).toContainText(value);
    }
    await expect(stats).toContainText("1 without an established path");
    await expect(page.getByText("npm 3 · PyPI 3")).toBeVisible();
    await expect(page.getByText("npm 3 · pip 3")).toBeVisible();
    await expect(page.getByText("4c8057c3bb")).toBeVisible();
    // Scoped to the page content: the project tabs above it now include a "Vulnerabilities" tab.
    await expect(page.getByTestId("project-content")).not.toContainText(/trust score|vulnerab|CVE-/i);
  });

  test("the table lists each dependency with its classification and source", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/dependencies"));
    const table = page.getByTestId("dependency-table");
    await expect(table.locator("tbody tr")).toHaveCount(nodes.length);

    const react = table.getByRole("row", { name: /react/ }).first();
    await expect(react).toContainText("19.2.7");
    await expect(react).toContainText("Direct");
    await expect(react).toContainText("OBSERVED");
    await expect(react).toContainText("web/package.json");

    const requests = table.getByRole("row", { name: /requests/ });
    await expect(requests).toContainText("unresolved");                                   // never a made-up version
    await expect(requests).toContainText("(>=2.31)");
    await expect(requests).toContainText("INFERRED");

    const orphan = table.getByRole("row", { name: /orphan/ });
    await expect(orphan).toContainText("Unknown");
    await expect(orphan).toContainText("UNKNOWN");
    await expect(orphan.getByRole("cell").nth(5)).toHaveText("—");                         // no depth claimed
  });

  test("opening a row shows where the dependency came from", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/dependencies"));
    await page.getByRole("button", { name: "Show evidence for flask" }).click();

    const evidence = page.getByTestId("dependency-evidence");
    await expect(evidence).toContainText("can also list transitive packages");             // the rule behind INFERRED
    await expect(evidence).toContainText("Exact version declared in backend/requirements.txt");
    await expect(evidence).toContainText("flask==3.0.0");
    await expect(evidence).toContainText("manifest · pip · runtime");
    const link = evidence.getByRole("link", { name: "backend/requirements.txt:3" });
    await expect(link).toHaveAttribute("href", "https://github.com/octo/demo/blob/4c8057c3bbed0e55f916341187cf4f2d3ddaaea6/backend/requirements.txt#L3");
    await expect(link).toHaveAttribute("rel", /noopener/);

    await page.getByRole("button", { name: "Hide evidence for flask" }).click();
    await expect(page.getByTestId("dependency-evidence")).toHaveCount(0);
  });

  test("filters are sent to the API and narrow the table", async ({ page }) => {
    const state = defaultState();
    await mockApi(page, state);
    await page.goto(projectUrl("/dependencies"));
    const rows = page.getByTestId("dependency-table").locator("tbody tr");
    await expect(rows).toHaveCount(6);

    await page.getByLabel("Ecosystem").selectOption("pypi");
    await expect(rows).toHaveCount(3);
    await page.getByLabel("Relationship").selectOption("DIRECT");
    await expect(rows).toHaveCount(2);
    await page.getByLabel("Unresolved versions only").check();
    await expect(rows).toHaveCount(1);
    await expect(page.getByText("1–1 of 1 (filtered from 6)")).toBeVisible();
    const last = state.requests.filter((r) => r.path.endsWith("/dependencies")).at(-1)!;
    expect(last.query).toMatchObject({ ecosystem: "pypi", relationship: "DIRECT", version_status: "UNRESOLVED", skip: "0" });

    await page.getByLabel("Unresolved versions only").uncheck();
    await page.getByLabel("Relationship").selectOption("");
    await page.getByLabel("Ecosystem").selectOption("");
    await page.getByLabel("Search by name").fill("sched");
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText("scheduler");

    await page.getByLabel("Search by name").fill("no-such-package");
    await expect(page.getByText("No dependencies match these filters.")).toBeVisible();
  });

  test("long lists are paged", async ({ page }) => {
    const many = Array.from({ length: 120 }, (_, i) => ({ ...nodes[0], node_id: `npm:pkg-${i}@1.0.0`, name: `pkg-${String(i).padStart(3, "0")}`, normalized_name: `pkg-${String(i).padStart(3, "0")}` }));
    const state = defaultState({ nodes: many });
    await mockApi(page, state);
    await page.goto(projectUrl("/dependencies"));
    const rows = page.getByTestId("dependency-table").locator("tbody tr");
    await expect(rows).toHaveCount(50);
    await expect(page.getByText("1–50 of 120")).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();
    await expect(page.getByText("51–100 of 120")).toBeVisible();
    await page.getByRole("button", { name: "Next" }).click();
    await expect(rows).toHaveCount(20);
    await expect(page.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(state.requests.filter((r) => r.path.endsWith("/dependencies")).at(-1)!.query.skip).toBe("100");
  });

  test("empty state: analysed, but no dependencies found", async ({ page }) => {
    await mockApi(page, defaultState({ nodes: [], edges: [] }));
    await page.goto(projectUrl("/dependencies"));
    await expect(page.getByTestId("no-dependencies")).toContainText("No dependencies were found");
    await expect(page.getByTestId("dependency-table")).toHaveCount(0);
    await expect(page.getByTestId("dependency-stats").getByText("Total dependencies").locator("..")).toContainText("0");
  });

  test("empty state: not analysed yet", async ({ page }) => {
    await mockApi(page, defaultState({ analysed: false, jobs: [null] }));
    await page.goto(projectUrl("/dependencies"));
    await expect(page.getByTestId("not-analysed")).toContainText("has not been analysed yet");
    await expect(page.getByTestId("dependency-stats")).toHaveCount(0);
    await page.getByRole("link", { name: "Go to overview" }).click();
    await expect(page.getByRole("button", { name: "Run dependency analysis" })).toBeVisible();
  });

  test("error state: the failure is shown and retry recovers", async ({ page }) => {
    const state = defaultState({ failures: { "/dependencies": 500 } });
    await mockApi(page, state);
    await page.goto(projectUrl("/dependencies"));
    await expect(page.getByRole("alert")).toContainText("Internal server error");
    await expect(page.getByTestId("dependency-table")).toHaveCount(0);
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("dependency-table").locator("tbody tr")).toHaveCount(6);
  });

  test("error state: a project that cannot be loaded", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto("/projects/665f000000000000000000ff/dependencies");
    await expect(page.getByRole("alert")).toContainText("Not found");
    await expect(page.getByRole("link", { name: "Back to projects" })).toBeVisible();
  });

  test("tabs move between overview, dependencies and graph", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/dependencies"));
    const tabs = page.getByRole("navigation", { name: "Project sections" });
    await tabs.getByRole("link", { name: "Dependency graph" }).click();
    await expect(page.getByTestId("dependency-graph")).toBeVisible();
    await tabs.getByRole("link", { name: "Overview" }).click();
    await expect(page.getByTestId("analysis-status")).toBeVisible();
  });
});
