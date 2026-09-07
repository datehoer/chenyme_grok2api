import assert from "node:assert/strict";
import { test } from "node:test";
import { settingsSchema } from "./settings-model.ts";

const duration = { value: 60, unit: "s" } as const;
const web = {
  baseURL: "https://grok.com", statsigMode: "url", statsigManualValue: "", statsigManualConfigured: false,
  statsigSignerURL: "https://grok.wodf.de/sign", clearanceMode: "on_demand", clearanceSolver: "cf-clearance-scraper",
  flareSolverrURL: "", clearanceSolverURL: "http://scraper:3000", clearanceSolverKey: "", clearanceSolverKeyConfigured: true,
  clearanceTimeout: duration, clearanceRefresh: duration, quotaTimeout: duration, chatTimeout: duration,
  streamIdleTimeout: duration, imageTimeout: duration, videoTimeout: duration, mediaConcurrency: 1, allowNSFW: false,
  freeVideoDurationCap: 6, recoveryBackoffBase: duration, recoveryBackoffMax: duration,
};

test("scraper settings do not require the hidden FlareSolverr URL", () => {
  assert.equal(settingsSchema.shape.providerWeb.safeParse(web).success, true);
});

test("each solver validates its own URL", () => {
  for (const value of [
    { ...web, clearanceSolverURL: "" },
    { ...web, clearanceSolver: "flaresolverr" },
  ]) {
    assert.equal(settingsSchema.shape.providerWeb.safeParse(value).success, false);
  }
  assert.equal(settingsSchema.shape.providerWeb.safeParse({ ...web, clearanceSolver: "flaresolverr", flareSolverrURL: "http://flaresolverr:8191", clearanceSolverURL: "" }).success, true);
});
