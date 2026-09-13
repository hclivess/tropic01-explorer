/**
 * Assert live mode against a running `tools/serve.py`.
 *
 *   PYTHONPATH=/path/to/ts-tvl python3 tools/serve.py --port 8800 &
 *   node tools/live_test.js http://127.0.0.1:8800
 *
 * The render test covers the static page; this covers the half that only exists
 * when a real model_server is behind it. It is separate because it needs that
 * server, and `check.sh` runs it only when EXPLORER_LIVE_URL is set — a missing
 * server should report SKIPPED, never pass quietly.
 *
 * jsdom has no `fetch`, so one is injected. That is the only accommodation; the
 * page is otherwise the file that ships.
 */
"use strict";

const { JSDOM } = require("jsdom");

const url = process.argv[2] || process.env.EXPLORER_LIVE_URL;
if (!url) {
  console.error("usage: node tools/live_test.js <url>");
  process.exit(2);
}

const failures = [];
const check = (name, actual, expected) => {
  const ok = actual === expected;
  console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}: ${actual}${ok ? "" : ` (expected ${expected})`}`);
  if (!ok) failures.push(name);
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  // The API must answer before the page is judged on whether it noticed.
  const health = await (await fetch(new URL("api/health", url))).json();
  check("api reports a live model", health.live, true);

  const errors = [];
  const dom = await JSDOM.fromURL(url, {
    runScripts: "dangerously",
    resources: "usable",
    beforeParse(w) {
      w.fetch = (u, o) => fetch(new URL(u, url), o);
      w.addEventListener("error", (e) => errors.push(e.message));
    },
  });
  await new Promise((r) => dom.window.addEventListener("load", () => setTimeout(r, 1500)));

  const d = dom.window.document;
  const $ = (id) => d.getElementById(id);

  check("page detected the model", $("live-badge").hidden, false);
  check("live panel shown", $("live-panel").hidden, false);
  check("no script errors", errors.length, 0);
  if (errors.length) errors.forEach((e) => console.log("        " + e));

  // Send: the bytes must come back from the model, not the capture.
  const before = $("live-out").textContent;
  $("live-send").click();
  await wait(1200);
  const after = $("live-out").textContent;
  check("sending produced a result", after !== before && after.length > 0, true);
  check("result carries a status code", /0x[0-9A-F]{2}/.test(after), true);

  // Power off must actually change state, and must disable sending. This is the
  // assertion that would have caught the power buttons silently issuing GETs.
  $("live-power").click();          // reads "power off" while powered
  await wait(900);
  check("power off is reflected",
    $("live-mode").textContent.includes("powered off"), true);
  check("power off disables sending", $("live-send").disabled, true);

  $("live-power").click();          // now reads "power on"
  await wait(1200);
  check("power on restores a mode",
    /APPLICATION|START_UP/.test($("live-mode").textContent), true);
  check("power on re-enables sending", $("live-send").disabled, false);

  check("no script errors after interaction", errors.length, 0);

  console.log();
  if (failures.length) {
    console.error(`${failures.length} failed: ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log("live mode ok");
  process.exit(0);
})().catch((e) => {
  console.error("FAILED:", e.message);
  process.exit(1);
});
