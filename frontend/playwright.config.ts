import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  workers: 1,
  retries: 0,
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:5173",
    browserName: "chromium",
    trace: "retain-on-failure",
  },
  reporter: "list",
});
