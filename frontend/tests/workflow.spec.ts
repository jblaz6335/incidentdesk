import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";

const env = Object.fromEntries(
  fs
    .readFileSync(path.resolve("../.env"), "utf8")
    .split(/\r?\n/)
    .filter((l) => l.includes("="))
    .map((l) => l.split("=", 2)),
);
test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Username", { exact: true }).fill("analyst");
  await page
    .getByLabel("Password", { exact: true })
    .fill(env.DEMO_ANALYST_PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Investigations", exact: true }),
  ).toBeVisible();
});
test("upload to investigation, escaped note, draft and report", async ({
  page,
}) => {
  await page.getByRole("button", { name: "Log uploads", exact: true }).click();
  const source = fs.readFileSync(
    path.resolve("../data/synthetic-events.jsonl"),
    "utf8",
  );
  const host = "WS-E2E-" + Date.now();
  await page
    .locator("input[type=file]")
    .setInputFiles({
      name: "browser-demo.jsonl",
      mimeType: "application/x-ndjson",
      buffer: Buffer.from(source.replaceAll("WS-FIN-07", host)),
    });
  await page.getByRole("button", { name: "Validate & queue" }).click();
  await expect(page.getByRole("status")).toContainText("Upload queued");
  await expect(
    page.getByText("completed", { exact: true }).first(),
  ).toBeVisible({ timeout: 30000 });
  await page
    .getByRole("button", { name: "Investigations", exact: false })
    .click();
  await expect(page.getByRole("button").filter({ hasText: host })).toBeVisible({
    timeout: 30000,
  });
  await page.getByRole("button").filter({ hasText: host }).click();
  await page.getByLabel("Case status").selectOption("investigating");
  await expect(page.getByRole("status")).toContainText("Case updated");
  await page.getByRole("tab", { name: "Analyst notes" }).click();
  await page
    .getByLabel("Investigation note")
    .fill(
      "<script>window.INJECTED=true</script> Observation requires validation.",
    );
  await page.getByRole("button", { name: "Add note", exact: true }).click();
  await expect(page.locator(".activity-list")).toContainText("<script>");
  expect(await page.evaluate(() => Object.hasOwn(window, "INJECTED"))).toBe(
    false,
  );
  await page.getByRole("tab", { name: "Report draft" }).click();
  await page.getByRole("button", { name: "Prepare draft" }).click();
  await expect(page.locator(".draft")).toContainText("U");
  await expect(
    page.getByText("Unreviewed draft", { exact: false }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "I reviewed the evidence", exact: false })
    .click();
  await expect(page.getByRole("status")).toContainText("Reviewed draft saved");
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export report" }).click();
  const report = await download;
  const file = await report.path();
  expect(fs.readFileSync(file!, "utf8")).toContain("SYNTHETIC DEMO DATA");
});
test("dashboard and evidence accessibility, screenshots and mobile layout", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await expect(
    page.getByRole("button", { name: "Open case 1", exact: true }),
  ).toBeVisible({ timeout: 30000 });
  expect(
    (await new AxeBuilder({ page }).analyze()).violations.map((v) => ({
      id: v.id,
      nodes: v.nodes.map((n) => ({
        target: n.target,
        summary: n.failureSummary,
      })),
    })),
  ).toEqual([]);
  await page.screenshot({
    path: "../docs/screenshots/dashboard.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Open case 1", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Why this case exists" }),
  ).toBeVisible();
  expect(
    (await new AxeBuilder({ page }).analyze()).violations.map((v) => ({
      id: v.id,
      nodes: v.nodes.map((n) => ({
        target: n.target,
        summary: n.failureSummary,
      })),
    })),
  ).toEqual([]);
  await page.screenshot({
    path: "../docs/screenshots/investigation.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "../docs/screenshots/mobile.png",
    fullPage: true,
  });
  expect(
    (await new AxeBuilder({ page }).analyze()).violations.map((v) => ({
      id: v.id,
      nodes: v.nodes.map((n) => ({
        target: n.target,
        summary: n.failureSummary,
      })),
    })),
  ).toEqual([]);
});
test("search empty state and malformed upload error", async ({ page }) => {
  await page
    .getByRole("textbox", { name: "Search cases" })
    .fill("nonexistent-host");
  await expect(
    page.getByRole("heading", { name: "No cases match these filters" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Log uploads", exact: true }).click();
  await page
    .locator("input[type=file]")
    .setInputFiles({
      name: "bad.jsonl",
      mimeType: "application/x-ndjson",
      buffer: Buffer.from("{}"),
    });
  await page.getByRole("button", { name: "Validate & queue" }).click();
  await expect(page.getByRole("alert")).toContainText("Line 1");
});
