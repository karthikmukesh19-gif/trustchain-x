import { expect, test } from "@playwright/test";

import { defaultState, mockApi, projectUrl } from "./mock-api";
import { components, makeSbom, makeSecurityJob, mockSecurity, securityState } from "./mock-security";
import type { SecurityState } from "./mock-security";

async function open(page: import("@playwright/test").Page, state: SecurityState) {
  await mockApi(page, defaultState({ analysed: state.analysed }));
  await mockSecurity(page, state);
  await page.goto(projectUrl("/sbom"));
}

test.describe("SBOM page", () => {
  test("a project without a dependency inventory is sent to the analysis first", async ({ page }) => {
    await open(page, securityState({ analysed: false, sboms: [], sbomJobs: [null] }));
    await expect(page.getByTestId("not-analysed")).toBeVisible();
    await expect(page.getByTestId("sbom-summary")).toHaveCount(0);
  });

  test("before any SBOM exists, none is shown", async ({ page }) => {
    await open(page, securityState({ sboms: [], sbomJobs: [null] }));
    await expect(page.getByTestId("no-sbom")).toContainText("No SBOM has been generated for this project");
    await expect(page.getByTestId("sbom-job").getByRole("button", { name: "Generate SBOM" })).toBeEnabled();
    await expect(page.getByTestId("sbom-job")).toContainText("no licences, hashes or versions are filled in");
    await expect(page.getByTestId("sbom-history")).toHaveCount(0);
  });

  test("generating shows queued, progress and then the new SBOM", async ({ page }) => {
    const state = securityState({
      sboms: [], afterGeneration: [makeSbom(1)],
      sbomJobs: [null, makeSecurityJob("sbom_generation", "queued"), makeSecurityJob("sbom_generation", "running"), makeSecurityJob("sbom_generation", "completed")],
    });
    await open(page, state);
    await page.getByRole("button", { name: "Generate SBOM" }).click();
    const job = page.getByTestId("sbom-job");
    await expect(job.getByText("Queued")).toBeVisible();
    await expect(job.getByRole("button", { name: "Generation in progress" })).toBeDisabled();
    await expect(page.getByTestId("sbom-summary")).toHaveCount(0);
    await expect(job.getByText("Generating a CycloneDX 1.5 SBOM for commit 4c8057c3bb")).toBeVisible();
    await expect(job.getByText("Completed")).toBeVisible();
    await expect(page.getByTestId("sbom-summary")).toContainText("SBOM version 1");
    expect(state.requests.filter((r) => r.method === "POST" && r.path.endsWith("/sbom/generate"))).toHaveLength(1);
  });

  test("the summary shows format, time, snapshot, counts, digests and integrity status", async ({ page }) => {
    await open(page, securityState());
    const summary = page.getByTestId("sbom-summary");
    await expect(summary).toContainText("SBOM version 2");
    await expect(summary).toContainText("CycloneDX 1.5 JSON");
    await expect(summary).toContainText("TrustChain-X 3.0.0");
    await expect(summary).toContainText("4c8057c3bb · main");
    await expect(summary.getByText("Components", { exact: true }).locator("..")).toContainText("5");
    await expect(summary).toContainText("1 without a resolved version · 2 with a recorded hash");
    await expect(summary).toContainText("Known to be incomplete");
    await expect(page.getByTestId("content-digest")).toHaveText("2c".repeat(32));
    await expect(summary).toContainText("2d".repeat(32));
    await expect(summary.getByText("Not verified yet")).toBeVisible();
    await expect(summary).toContainText("integrity-verifiable");
    await expect(summary).toContainText("not cryptographically signed");
    await expect(page.getByTestId("project-content")).not.toContainText(/tamper-proof|trust score|risk score/i);
  });

  test("verifying an intact SBOM lists every check as passed", async ({ page }) => {
    const state = securityState();
    await open(page, state);
    await page.getByRole("button", { name: "Verify integrity" }).click();
    const result = page.getByTestId("verification-result");
    await expect(result).toContainText("Integrity verified");
    for (const label of ["Stored document matches its recorded digest", "Stored document is in canonical form", "Content matches the recorded content digest",
      "Component records match the document", "Regenerating from the snapshot gives the same content"]) await expect(result).toContainText(label);
    await expect(page.getByTestId("sbom-summary").getByText("Verified", { exact: true })).toBeVisible();
    expect(state.requests.filter((r) => r.method === "POST" && r.path.endsWith("/sbom/sbom2/verify"))).toHaveLength(1);
  });

  test("a modified SBOM fails verification and the failed checks are named", async ({ page }) => {
    await open(page, securityState({ failedChecks: ["stored_document_digest", "regeneration"] }));
    await page.getByRole("button", { name: "Verify integrity" }).click();
    const result = page.getByTestId("verification-result");
    await expect(result).toHaveAttribute("role", "alert");
    await expect(result).toContainText("Integrity verification failed");
    await expect(result).toContainText("Simulated failure of stored_document_digest.");
    await expect(result).toContainText("Simulated failure of regeneration.");
    await expect(result).toContainText("Compared with a fresh generation from the snapshot: 0 added, 0 removed, 1 changed component(s); 1 relationship");
    await expect(page.getByTestId("sbom-summary").getByText("Verification failed", { exact: true })).toBeVisible();
    await expect(page.getByTestId("sbom-history").getByText("Verification failed")).toBeVisible();
  });

  test("a verification request that fails is reported, not shown as a result", async ({ page }) => {
    await open(page, securityState({ failures: { "/verify": 500 } }));
    await page.getByRole("button", { name: "Verify integrity" }).click();
    await expect(page.getByTestId("sbom-summary").getByRole("alert")).toContainText("Internal server error");
    await expect(page.getByTestId("verification-result")).toHaveCount(0);
    await expect(page.getByTestId("sbom-summary").getByText("Not verified yet")).toBeVisible();
  });

  test("changes from the previous version list added, removed and changed components", async ({ page }) => {
    const state = securityState();
    await open(page, state);
    const changes = page.getByTestId("sbom-diff");
    await expect(changes).toContainText("1 added");
    await expect(changes).toContainText("1 removed");
    await expect(changes).toContainText("2 changed");
    await expect(changes).toContainText("4 → 5 components");
    const added = changes.getByRole("row", { name: /right/ });
    await expect(added).toContainText("ADDED");
    await expect(added).toContainText("Newly introduced dependency");
    await expect(changes.getByRole("row", { name: /golang.org\/x\/crypto/ })).toContainText("REMOVED");
    const requests = changes.getByRole("row", { name: /requests/ });
    await expect(requests).toContainText("CHANGED");
    await expect(requests.getByRole("cell").nth(2)).toHaveText("2.19.1");
    await expect(requests.getByRole("cell").nth(3)).toHaveText("2.32.0");
    await expect(changes.getByRole("row", { name: /xlsx/ })).toContainText("Metadata: hashes");
    expect(state.requests.some((r) => r.path.endsWith("/sbom/sbom1/diff/sbom2"))).toBeTruthy();    // previous -> shown
  });

  test("a single SBOM has nothing to be compared with", async ({ page }) => {
    await open(page, securityState({ sboms: [makeSbom(1)] }));
    await expect(page.getByTestId("sbom-changes")).toContainText("This is the only SBOM of the project");
    await expect(page.getByTestId("sbom-diff")).toHaveCount(0);
  });

  test("components show version, package URL, recorded hash and linked advisories", async ({ page }) => {
    await open(page, securityState());
    const table = page.getByTestId("component-table");
    await expect(table.locator("tbody tr")).toHaveCount(components.length);
    const xlsx = table.getByRole("row", { name: /xlsx/ });
    for (const text of ["0.18.5", "npm", "pkg:npm/xlsx@0.18.5", "SHA-512", "GHSA-4r6h-8v6p-xvw6"]) await expect(xlsx).toContainText(text);
    const flask = table.getByRole("row", { name: /flask/ });
    await expect(flask).toContainText("unresolved");                                               // never a made-up version
    await expect(flask).toContainText("none recorded");                                            // never a made-up hash
    const requests = table.getByRole("row", { name: /requests/ });
    await expect(requests).toContainText("PYSEC-2018-28");
    await expect(requests).toContainText("Unknown");
    await expect(page.getByTestId("sbom-linkage")).toContainText("2 components of this SBOM have 3 stored advisory matches");
    await expect(page.getByTestId("sbom-linkage").getByRole("link", { name: "View findings" })).toHaveAttribute("href", /\/vulnerabilities$/);
  });

  test("components can be searched and limited to those with advisory matches", async ({ page }) => {
    const state = securityState();
    await open(page, state);
    const rows = page.getByTestId("component-table").locator("tbody tr");
    await page.getByLabel("With advisory matches only").check();
    await expect(rows).toHaveCount(2);
    await page.getByLabel("With advisory matches only").uncheck();
    await page.getByLabel("Search components by name").fill("flask");
    await expect(rows).toHaveCount(1);
    await page.getByLabel("Search components by name").fill("zzz");
    await expect(page.getByTestId("sbom-components")).toContainText("No components match these filters.");
    const queries = state.requests.filter((r) => r.path.endsWith("/components")).map((r) => r.query);
    expect(queries.some((q) => q.only_vulnerable === "true")).toBeTruthy();
    expect(queries.some((q) => q.q === "flask")).toBeTruthy();
  });

  test("without stored matches, linkage says so without claiming the components are safe", async ({ page }) => {
    await open(page, securityState({ components: components.map((c) => ({ ...c, vulnerabilities: [] })) }));
    const linkage = page.getByTestId("sbom-linkage");
    await expect(linkage).toContainText("No advisory matches are stored for this SBOM's snapshot");
    await expect(linkage).toContainText("or no vulnerability check has been run for it");
  });

  test("history lists every version and an earlier one can be opened and compared", async ({ page }) => {
    const state = securityState();
    await open(page, state);
    const history = page.getByTestId("sbom-history");
    await expect(history.locator("tbody tr")).toHaveCount(2);
    await expect(history.locator("tbody tr").first()).toContainText("Shown above");
    await expect(history.locator("tbody tr").nth(1)).toContainText("1111111111");
    await history.getByRole("button", { name: "View version 1" }).click();
    const summary = page.getByTestId("sbom-summary");
    await expect(summary).toContainText("SBOM version 1");
    await expect(summary.getByText("Earlier version")).toBeVisible();
    await expect(page.getByTestId("content-digest")).toHaveText("1c".repeat(32));
    await expect.poll(() => state.requests.some((r) => r.path.endsWith("/sbom/sbom2/diff/sbom1"))).toBeTruthy();
    await expect(page.getByLabel("SBOM version to compare with")).toHaveValue("sbom2");
  });

  test("download fetches the stored document as a file", async ({ page }) => {
    const state = securityState();
    await open(page, state);
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download" }).click();
    expect((await download).suggestedFilename()).toBe("sbom-v2-4c8057c3bb.cdx.json");
    expect(state.requests.some((r) => r.path.endsWith("/sbom/sbom2/document"))).toBeTruthy();
  });

  test("a failed generation shows the reason and stores nothing", async ({ page }) => {
    const failed = makeSecurityJob("sbom_generation", "failed", { error: { code: "NOT_ANALYSED", message: "Run a dependency analysis first: an SBOM is generated from the dependency inventory." } });
    await open(page, securityState({ sboms: [], sbomJobs: [failed] }));
    const job = page.getByTestId("sbom-job");
    await expect(job.getByRole("alert")).toContainText("SBOM generation failed. No SBOM was stored from this run.");
    await expect(job.getByRole("alert")).toContainText("NOT_ANALYSED");
    await expect(page.getByTestId("no-sbom")).toBeVisible();
  });

  test("a refused generation and a server error are explained", async ({ page }) => {
    const state = securityState({ startStatus: 409 });
    await open(page, state);
    await page.getByRole("button", { name: "Generate again" }).click();
    await expect(page.getByTestId("sbom-job").getByRole("alert")).toContainText("Another job is already queued or running");

    const broken = securityState({ failures: { "/sbom": 500 } });
    await mockSecurity(page, broken);
    await page.goto(projectUrl("/sbom"));
    await expect(page.getByRole("alert").filter({ hasText: "Internal server error" })).toBeVisible();
    broken.failures = {};
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByTestId("sbom-summary")).toBeVisible();
  });
});
