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
