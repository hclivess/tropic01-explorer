/**
 * Render docs/index.html in a headless DOM and assert it actually works.
 *
 * The page is generated-data-driven, so the failure mode to catch is not "the
 * HTML is malformed" but "the model changed shape and the renderer silently
 * drew nothing". Every assertion below is therefore about *counts derived from
 * the spec*, not hard-coded numbers: if ts-tvl grows a register or a request,
 * this still passes; if the page stops rendering one, it fails.
 *
 *   npm install jsdom && node tools/render_test.js
 */
"use strict";

const { JSDOM } = require("jsdom");
const fs = require("fs");
const path = require("path");

const DOCS = path.join(__dirname, "..", "docs");
const failures = [];
const check = (name, actual, expected) => {
  const ok = actual === expected;
  console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}: ${actual}${ok ? "" : ` (expected ${expected})`}`);
  if (!ok) failures.push(name);
};

const spec = (() => {
  const js = fs.readFileSync(path.join(DOCS, "model_spec.js"), "utf8");
  const sandbox = {};
  new Function("window", js)(sandbox);
  return sandbox.MODEL_SPEC;
})();

const errors = [];
const dom = new JSDOM(fs.readFileSync(path.join(DOCS, "index.html"), "utf8"), {
  runScripts: "dangerously",
  resources: "usable",              // so <script src="model_spec.js"> loads
  url: "file://" + DOCS + "/index.html",
  beforeParse(win) {
    win.addEventListener("error", (e) => errors.push(e.message));
  },
});

dom.window.addEventListener("load", () => {
  const d = dom.window.document;
  const n = (sel) => d.querySelectorAll(sel).length;

  console.log(`spec: ts-tvl ${spec.provenance.ts_tvl_describe}\n`);

  // Every count assertion below compares the page against the spec, which is
  // satisfied vacuously when the spec is empty: 0 rendered === 0 expected.
  // Floor the spec first, so a capture that produced nothing fails here rather
  // than passing green with a blank page.
  const atLeast = (name, n, min) => {
    const ok = n >= min;
    console.log(`${ok ? "  ok  " : "  FAIL"}  spec has ${name}: ${n}${ok ? "" : ` (need >= ${min})`}`);
    if (!ok) failures.push("spec " + name);
  };
  atLeast("chip modes", spec.chip_modes.length, 2);
  atLeast("CO registers", spec.co_registers.length, 1);
  atLeast("L2 requests", spec.l2_requests.length, 1);
  atLeast("boot transitions", spec.boot_transitions.length, 1);
  atLeast("wire traces", spec.wire_traces.length, 1);
  atLeast("CHIP_STATUS flags", spec.chip_status_flags.length, 1);
  atLeast("FW header fields", spec.fw_banks.fields.length, 1);
  console.log();

  check("script errors", errors.length, 0);
  if (errors.length) errors.forEach((e) => console.log("        " + e));

  // structure
  check("tabs", n("nav button"), 6);
  check("nested tables (invalid HTML)", n("table table"), 0);
  check("empty tables", n("table:not(:has(tbody tr))"), 0);

  // everything in the spec must reach the page
  const words = spec.co_address_space.size_bytes / spec.co_address_space.register_size_bytes;
  check("CO address-space cells", n("#map .cell"), words);
  check("CO registers listed", n("#t-co tbody tr"), spec.co_registers.length);
  check("clickable registers", n("#map .cell[data-name]"), spec.co_registers.length);
  check("boot transitions", n("#t-boot tbody tr"), spec.boot_transitions.length);
  check("L2 requests", n("#t-l2 tbody tr"), spec.l2_requests.length);
  check("wire traces", n("#wire .panel"), spec.wire_traces.length);
  check("FW header fields", n("#fwhdr tbody tr"), spec.fw_banks.fields.length);
  check("FW bank ids", n("#t-banks tbody tr"), spec.fw_banks.bank_ids.length);
  const oidRows = Object.values(spec.get_info_objects).reduce((a, v) => a + v.length, 0);
  check("Get_Info object rows", n("#t-oid tbody tr"), oidRows);
  check("CHIP_STATUS bit chips", n("#r-bits .bit"), spec.chip_status_flags.length);

  // cells must be real elements, not markup rendered as text
  check("tag cells rendered as elements", n("#t-l2 .tag") > 0, true);
  check("no literal markup in table text",
    /<span|&lt;span/.test(d.querySelector("#t-l2").textContent), false);

  // facts that used to be hard-coded in the prose now come from the spec
  const words2 = spec.co_address_space.size_bytes / spec.co_address_space.register_size_bytes;
  check("CO facts injected from spec",
    d.getElementById("co-facts").textContent.includes(String(words2)), true);
  check("application CO base injected",
    [...d.querySelectorAll(".appbase")].every((x) => x.textContent.length > 0), true);
  check("FW header size injected",
    d.getElementById("fw-size").textContent
      .includes(String(spec.fw_banks.header_size)), true);

  // the header must say where the data came from
  const prov = d.getElementById("prov").textContent;
  check("provenance names the commit",
    prov.includes(spec.provenance.ts_tvl_describe), true);

  // the boot panel must actually drive off the captured table
  const button = (re) => [...d.querySelectorAll("#acts button")]
    .find((b) => re.test(b.textContent));
  const maint = button(/maintenance/);
  check("maintenance action present", !!maint, true);
  if (maint) {
    maint.click();
    const expected = spec.boot_transitions.find(
      (r) => r.from === "APPLICATION" && r.action === "MAINTENANCE_REBOOT" &&
             r.maintenance_ena === 1 && r.has_riscv_fw === true
    );
    check("maintenance reboot lands where the capture says",
      d.getElementById("r-mode").textContent, expected.to);
  }

  // and the fix this repo exists to visualise: disabled means refused
  const off = [...d.querySelectorAll("#seg-maint button")]
    .find((b) => /disabled/.test(b.textContent));
  if (off) {
    off.click();
    const b2 = button(/maintenance/);
    if (b2 && !b2.disabled) {
      b2.click();
      const row = spec.boot_transitions.find(
        (r) => r.action === "MAINTENANCE_REBOOT" && r.maintenance_ena === 0
      );
      check("MAINTENANCE_ENA=0 shows the captured refusal",
        d.getElementById("r-status").textContent.startsWith(
          "0x" + row.l2_status.toString(16).toUpperCase()), true);
    }
  }

  check("errors after interaction", errors.length, 0);

  console.log();
  if (failures.length) {
    console.error(`${failures.length} failed: ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log("all checks passed");
});
