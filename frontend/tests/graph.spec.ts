import { expect, test } from "@playwright/test";

import { defaultState, mockApi, nodes, projectUrl } from "./mock-api";

const transform = (page: import("@playwright/test").Page) =>
  page.locator(".react-flow__viewport").evaluate((element) => getComputedStyle(element).transform);

test.describe("dependency graph", () => {
  test("draws the project, every package and every edge from the data", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/graph"));

    await expect(page.getByTestId("graph-root")).toContainText("octo/demo");
    const drawn = page.getByTestId("graph-node");
    await expect(drawn).toHaveCount(nodes.length);                                          // no extra nodes for presentation
    await expect(page.locator(".react-flow__edge")).toHaveCount(5);
    await expect(page.getByTestId("graph-summary")).toContainText("Showing 6 of 6 packages and 5 of 5 edges");

    await expect(page.locator('[data-testid="graph-node"][data-relationship="DIRECT"]')).toHaveCount(3);
    await expect(page.locator('[data-testid="graph-node"][data-relationship="TRANSITIVE"]')).toHaveCount(2);
    await expect(page.locator('[data-testid="graph-node"][data-relationship="UNKNOWN"]')).toHaveCount(1);
    await expect(page.locator('[data-testid="graph-node"][data-depth="3"]')).toContainText("loose-envify");
    await expect(page.locator('[data-testid="graph-node"][data-depth="none"]')).toContainText("orphan");
    await expect(drawn.filter({ hasText: "requests" })).toContainText("unresolved");
    await expect(page.getByText("1 package(s) have no established path and are drawn unconnected.")).toBeVisible();
  });

  test("deeper packages are placed further right", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/graph"));
    const x = async (testId: string, text?: string) => {
      const locator = text ? page.getByTestId(testId).filter({ hasText: text }) : page.getByTestId(testId);
      return (await locator.boundingBox())!.x;
    };
    const [root, direct, second, third] = [await x("graph-root"), await x("graph-node", "react"), await x("graph-node", "scheduler"), await x("graph-node", "loose-envify")];
    expect(root).toBeLessThan(direct);
    expect(direct).toBeLessThan(second);
    expect(second).toBeLessThan(third);
  });

  test("zoom and pan change the viewport", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/graph"));
    await expect(page.getByTestId("graph-node")).toHaveCount(6);
    const initial = await transform(page);

    await page.locator(".react-flow__controls-zoomin").click();
    await expect.poll(() => transform(page)).not.toBe(initial);
    const zoomed = await transform(page);

    const pane = (await page.locator(".react-flow__pane").boundingBox())!;
    await page.mouse.move(pane.x + pane.width - 40, pane.y + pane.height - 40);
    await page.mouse.down();
    await page.mouse.move(pane.x + pane.width - 160, pane.y + pane.height - 120, { steps: 6 });
    await page.mouse.up();
    await expect.poll(() => transform(page)).not.toBe(zoomed);

    await page.locator(".react-flow__controls-fitview").click();
    await expect(page.locator(".react-flow__minimap")).toBeVisible();
  });

  test("selecting a package shows its paths and evidence", async ({ page }) => {
    const state = defaultState();
    await mockApi(page, state);
    await page.goto(projectUrl("/graph"));
    const details = page.getByTestId("graph-details");
    await expect(details).toContainText("Select a package in the graph");

    await page.getByTestId("graph-node").filter({ hasText: "loose-envify" }).click();
    await expect(details.getByRole("heading", { name: "loose-envify" })).toBeVisible();
    await expect(details).toContainText("octo/demo  →  react@19.2.7  →  scheduler@0.27.0  →  loose-envify@1.4.0");
    await expect(details.getByTestId("dependency-evidence")).toContainText("Transitive");
    await expect(details.getByTestId("dependency-evidence")).toContainText("OBSERVED");
    expect(state.requests.some((r) => r.path.endsWith("/dependencies/paths") && r.query.to === "npm:loose-envify@1.4.0")).toBe(true);

    await details.getByRole("button", { name: "Close details" }).click();
    await expect(details).toContainText("Select a package in the graph");
  });

  test("a package with no established path says so instead of showing a path", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/graph"));
    await page.getByTestId("graph-node").filter({ hasText: "orphan" }).click();
    await expect(page.getByTestId("graph-details")).toContainText("does not establish how the project reaches this package");
  });

  test("filters narrow what is drawn", async ({ page }) => {
    await mockApi(page, defaultState());
    await page.goto(projectUrl("/graph"));
    const drawn = page.getByTestId("graph-node");
    await expect(drawn).toHaveCount(6);

    await page.getByLabel("Depth").selectOption("1");
    await expect(drawn).toHaveCount(3);
    await expect(page.locator(".react-flow__edge")).toHaveCount(3);
    await expect(page.getByTestId("graph-summary")).toContainText("Showing 3 of 6 packages");

    await page.getByLabel("Depth").selectOption("");
    await page.getByLabel("Ecosystem").selectOption("npm");
    await expect(drawn).toHaveCount(3);
    await page.getByLabel("Relationship").selectOption("TRANSITIVE");
    await expect(drawn).toHaveCount(2);
    await page.getByLabel("Relationship").selectOption("");
    await page.getByLabel("Ecosystem").selectOption("");
    await page.getByLabel("Search by name").fill("flask");
    await expect(drawn).toHaveCount(1);
    await page.getByLabel("Search by name").fill("zzz");
    await expect(page.getByText("No packages match these filters.")).toBeVisible();
  });

  test("large graphs are capped and say how much is hidden", async ({ page }) => {
    const many = Array.from({ length: 400 }, (_, i) => ({ ...nodes[0], node_id: `npm:pkg-${i}@1.0.0`, name: `pkg-${i}`, normalized_name: `pkg-${i}`, depth: 1 + (i % 4) }));
    await mockApi(page, defaultState({ nodes: many, edges: [] }));
    await page.goto(projectUrl("/graph"));
    await expect(page.getByTestId("graph-summary")).toContainText("Showing 250 of 400 packages");
    await expect(page.getByTestId("graph-summary")).toContainText("150 matching packages are not drawn");
  });

  test("empty state: analysed with no dependencies", async ({ page }) => {
    await mockApi(page, defaultState({ nodes: [], edges: [] }));
    await page.goto(projectUrl("/graph"));
    await expect(page.getByTestId("empty-graph")).toContainText("There is no graph to draw");
    await expect(page.getByTestId("dependency-graph")).toHaveCount(0);
    await expect(page.getByTestId("graph-node")).toHaveCount(0);
  });

  test("empty state: not analysed yet", async ({ page }) => {
    await mockApi(page, defaultState({ analysed: false, jobs: [null] }));
    await page.goto(projectUrl("/graph"));
    await expect(page.getByTestId("not-analysed")).toBeVisible();
    await expect(page.getByTestId("dependency-graph")).toHaveCount(0);
  });

  test("error state: the failure is shown and retry recovers", async ({ page }) => {
    const state = defaultState({ failures: { "/dependencies/graph": 500 } });
    await mockApi(page, state);
    await page.goto(projectUrl("/graph"));
    await expect(page.getByRole("alert")).toContainText("Internal server error");
    state.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("graph-node")).toHaveCount(6);
  });

  test("a failure loading one package's evidence is shown in the panel", async ({ page }) => {
    const state = defaultState();
    await mockApi(page, state);
    await page.goto(projectUrl("/graph"));
    await expect(page.getByTestId("graph-node")).toHaveCount(6);
    state.failures = { "/dependencies/paths": 500 };
    await page.getByTestId("graph-node").filter({ hasText: "flask" }).click();
    await expect(page.getByTestId("graph-details").getByRole("alert")).toContainText("Internal server error");
  });
});
