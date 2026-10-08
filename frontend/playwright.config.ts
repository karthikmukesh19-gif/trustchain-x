import { defineConfig, devices } from "@playwright/test";

// The tests run the built application in a real browser and answer every /api
// request themselves, so they need neither the backend nor network access.
//
//   npm run test:install   (once: downloads Chromium)
//   npm test
//
// Set PLAYWRIGHT_BASE_URL to test an already running frontend instead of
// building and previewing one.
const externalUrl = process.env.PLAYWRIGHT_BASE_URL;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  timeout: 30_000,
  expect: { timeout: 7_000 },
  use: {
    baseURL: externalUrl ?? "http://localhost:4173",
    trace: "retain-on-failure",
    launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1400, height: 900 } } }],
  webServer: externalUrl
    ? undefined
    : {
        command: "npm run build && npm run preview -- --port 4173 --strictPort",
        url: "http://localhost:4173",
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
      },
});
