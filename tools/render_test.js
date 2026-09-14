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

// Mirror the page's hex(): pad to two digits. Writing "0x" + n.toString(16)
// here passes for 0x7E and silently fails for 0x01, which is how this was
// caught - by a value that happened to be one digit.
const hex = (n) => "0x" + n.toString(16).toUpperCase().padStart(2, "0");

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

// If the page never loads, or a check throws half-way, the handler below never
// reaches its exit(1) - and node then exits 0 with FAIL lines on screen. Both
// happened. Crash loudly instead: a gate that can pass while failing is worse
// than no gate.
const watchdog = setTimeout(() => {
  console.error("render test: the page never finished loading");
  process.exit(1);
}, 30000);
dom.window.addEventListener("load", () => {
  clearTimeout(watchdog);
  run().catch((e) => {
    console.error("render test crashed mid-way: " + ((e && e.stack) || e));
    process.exit(1);
  });
});

async function run() {
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
  // Every Try-it exchange has a walkthrough - same list, same run.
  atLeast("walkthrough scenarios", (spec.walkthroughs || { scenarios: [] }).scenarios.length, spec.exchanges.length);
  (spec.walkthroughs || { scenarios: [] }).scenarios.forEach((sc) =>
    atLeast("steps in '" + sc.title + "'", sc.steps.length, 5));
  atLeast("walkthrough source excerpts", Object.keys((spec.walkthroughs || { sources: {} }).sources).length, 3);
  atLeast("boot transitions with wire bytes",
    spec.boot_transitions.filter((r) => r.request && r.response).length, 1);
  atLeast("wire traces", spec.wire_traces.length, 1);
  atLeast("CHIP_STATUS flags", spec.chip_status_flags.length, 1);
  atLeast("FW header fields", spec.fw_banks.fields.length, 1);
  console.log();

  check("script errors", errors.length, 0);
  if (errors.length) errors.forEach((e) => console.log("        " + e));

  // structure
  // Derived, not a magic number: one nav button per tab section, so adding a
  // tab does not require editing this file (and forgetting to wire its button
  // still fails).
  check("a nav button per tab section", n("nav button"), n('section[id^="tab-"]'));
  check("nested tables (invalid HTML)", n("table table"), 0);
  check("empty tables", n("table:not(:has(tbody tr))"), 0);

  // everything in the spec must reach the page
  const words = spec.co_address_space.size_bytes / spec.co_address_space.register_size_bytes;
  check("CO address-space cells", n("#map .cell"), words);
  check("CO registers listed", n("#t-co tbody tr"), spec.co_registers.length);
  check("clickable registers", n("#map .cell[data-name]"), spec.co_registers.length);
  check("boot transitions", n("#t-boot tbody tr"), spec.boot_transitions.length);
  check("boot rows link to their Try-it exchange", n("#t-boot button.linkish"),
    spec.boot_transitions.filter((r) => r.action !== "POWER_ON").length);
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
    // and shows the frames that did it, decoded the way Try-it decodes them
    const bb = d.getElementById("boot-bytes");
    check("boot panel shows request and response frames", bb.querySelectorAll(".frame").length, 2);
    check("boot panel request frame carries the captured REQ_ID",
      bb.textContent.includes(hex(parseInt(expected.request.slice(0, 2), 16))), true);
    check("boot panel response frame carries the captured STATUS",
      bb.textContent.includes(hex(parseInt(expected.response.slice(0, 2), 16))), true);
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
        d.getElementById("r-status").textContent.startsWith(hex(row.l2_status)), true);
    }
  }

  // the Try-it explorer must actually look requests up in the capture
  atLeast("exchanges", spec.exchanges.length, 2);
  const pick = d.getElementById("try-pick");
  check("request dropdown populated",
    pick.querySelectorAll("option").length,
    new Set(spec.exchanges.map((e) => e.group + " · " + e.label)).size);
  check("dropdown is grouped", pick.querySelectorAll("optgroup").length > 1, true);

  // drive it: choose the request whose answer differs most between modes
  const gated = spec.exchanges.find((e) => e.status === 0x7e);
  if (gated) {
    const key = gated.group + " · " + gated.label;
    pick.value = key;
    pick.dispatchEvent(new dom.window.Event("change"));
    const modeBtns = [...d.querySelectorAll("#try-mode button")];
    const modeBtn = modeBtns.find((b) => b.textContent === gated.mode);
    check("mode button for the gated case exists", !!modeBtn, true);

    // Switching mode must actually redraw. Click the mode that is NOT already
    // selected: clicking the selected one is a no-op that passes whatever the
    // handler does, which is exactly how a broken selector shipped once.
    const notSelected = modeBtns.find((b) => b.getAttribute("aria-pressed") !== "true");
    if (notSelected) {
      const paneBefore = d.getElementById("try-main").textContent;
      const bootLogBefore = d.getElementById("log").textContent;
      notSelected.click();
      check("switching mode redraws the pane",
        d.getElementById("try-main").textContent !== paneBefore, true);
      check("switching mode marks the new button pressed",
        notSelected.getAttribute("aria-pressed"), "true");
      // The two panels are deliberately one chip now: switching mode here must
      // move the boot panel's readout and say so in its log. (This assertion
      // used to demand the opposite, and the pre-push hook caught the
      // contradiction the moment the behaviour changed.)
      check("mode change moves the boot readout",
        d.getElementById("r-mode").textContent, notSelected.textContent);
      check("mode change is recorded in the boot log",
        d.getElementById("log").textContent !== bootLogBefore, true);
      check("direct set clears the stale transition status",
        d.getElementById("r-status").textContent, "—");
    }

    if (modeBtn) {
      modeBtn.click();
      const shown = d.getElementById("try-main").textContent;
      check("gated request shows its captured status",
        shown.includes(hex(gated.status)), true);
      const other = spec.exchanges.find(
        (e) => e.mode !== gated.mode && e.group + " · " + e.label === key);
      if (other) {
        check("other-mode pane shows the counterpart status",
          d.getElementById("try-other").textContent.includes(hex(other.status)), true);
      }
    }
  }

  // the repository's own examples must all reach the page
  atLeast("examples", (spec.examples || []).length, 1);
  check("example panels", n("#examples > .panel"), spec.examples.length);
  check("example sources shown", n("#examples .src"), spec.examples.length);
  const totalCalls = spec.examples.reduce((a, x) => a + x.calls.length, 0);
  check("example exchanges shown", n("#examples .call"), totalCalls);
  const l3Calls = spec.examples.reduce(
    (a, x) => a + x.calls.filter((c) => c.kind === "L3").length, 0);
  check("L3 exchanges marked", n("#examples .call.l3"), l3Calls);
  const streams = spec.examples.reduce(
    (a, x) => a + (x.stdout ? 1 : 0) + (x.logs ? 1 : 0), 0);
  check("captured output streams shown", n("#examples .out"), streams);
  check("log streams shown", n("#examples .out.logstream"),
    spec.examples.filter((x) => x.logs).length);
  // every example calls setup_logging(), so every one must have a log
  check("every example captured its log",
    spec.examples.filter((x) => x.logs).length, spec.examples.length);
  check("logs carry no object addresses",
    spec.examples.some((x) => / at 0x[0-9a-f]{6,}>/.test(x.logs || "")), false);
  check("no example raised", spec.examples.filter((x) => x.error).length, 0);
  // masking must be visible wherever the capture says bytes moved
  const anyVolatile = spec.examples.some((x) => x.any_volatile);
  check("session-dependent bytes are marked", n("#examples .vol") > 0, anyVolatile);

  // constants, read off tvl/constants.py
  const entries = spec.constants.enums.reduce((a, e) => a + e.members.length, 0)
    + spec.constants.values.length;
  atLeast("constant entries", entries, 10);
  check("enum panels", n("#const-enums > .panel"), spec.constants.enums.length);
  check("value rows", n("#const-values tbody tr"), spec.constants.values.length);
  check("version examples", n("#const-versions tbody tr"),
    spec.constants.fw_version_examples.length);
  const search = d.getElementById("const-search");
  search.value = "version";
  search.dispatchEvent(new dom.window.Event("input"));
  check("filtering narrows the list",
    n("#const-values tbody tr") < spec.constants.values.length, true);
  search.value = "";
  search.dispatchEvent(new dom.window.Event("input"));
  check("clearing the filter restores it",
    n("#const-values tbody tr"), spec.constants.values.length);

  // Byte order: L2 is little-endian throughout, so the page must not offer a
  // choice. The one big-endian thing in the codebase is CO storage, which never
  // reaches the wire.
  const single = spec.constants.values.find(
    (v) => v.kind === "int" && v.value <= 0xff);
  const multi = spec.constants.values.find(
    (v) => v.kind === "int" && v.value > 0xff);
  const rows = [...d.querySelectorAll("#const-values tbody tr.pick")];
  const rowFor = (name) => rows.find((r) => r.cells[0].textContent === name);
  if (single && rowFor(single.name)) {
    const r = rowFor(single.name);
    r.click();
    check("single-byte value shows no byte order",
      /endian/.test(r.nextSibling.textContent), false);
    r.click();
  }
  if (multi && rowFor(multi.name)) {
    const r = rowFor(multi.name);
    r.click();
    const text = r.nextSibling.textContent;
    check("multi-byte value shows little-endian", /little-endian/.test(text), true);
    check("multi-byte value does not offer big-endian",
      /big-endian/.test(text), false);
    r.click();
  }

  // Multi-byte hex must never be rendered unspaced: "2b92" reads as the value
  // 0x2b92, but those are the wire bytes of 0x922B. The CRC was the one place
  // this survived.
  const chipId = spec.exchanges.find(
    (e) => e.decoded && e.decoded.kind === "chip_id");
  if (chipId) {
    const sel2 = d.getElementById("try-pick");
    sel2.value = chipId.group + " · " + chipId.label;
    sel2.dispatchEvent(new dom.window.Event("change"));
    const crcField = [...d.querySelectorAll("#try-main .fld")]
      .find((f) => f.querySelector(".n").textContent === "CRC16");
    check("CRC is rendered as spaced bytes", /^[0-9a-f]{2} [0-9a-f]{2}/.test(
      crcField.textContent.replace("CRC16", "").trim()), true);
    check("CRC also shows its value", /= 0x[0-9A-F]{4}/.test(crcField.textContent), true);
  }
  // and the CO tab must name the one big-endian thing in the codebase
  check("CO tab names its big-endian storage",
    /big-endian/.test(d.getElementById("tab-co").textContent), true);

  // decoded payloads in Try it
  const decodable = spec.exchanges.filter((e) => e.decoded).length;
  atLeast("decodable exchanges", decodable, 1);
  const vsn = spec.exchanges.find(
    (e) => e.decoded && e.decoded.kind === "fw_version");
  if (vsn) {
    const k = vsn.group + " · " + vsn.label;
    const sel = d.getElementById("try-pick");
    sel.value = k;
    sel.dispatchEvent(new dom.window.Event("change"));
    check("payload is decoded, not just hex",
      d.querySelector("#try-main .decoded") !== null, true);
    check("decoded shows the version string",
      d.querySelector("#try-main .decoded").textContent.includes(vsn.decoded.version),
      true);
  }

  // every table row that names a request must be able to show it happening
  check("L2 rows link to an exchange",
    n("#t-l2 .linkish"), spec.l2_requests.length);
  check("Get_Info rows link to an exchange", n("#t-oid .linkish"),
    Object.values(spec.get_info_objects).reduce((a, v) => a + v.length, 0));
  check("FW bank rows link to an exchange",
    n("#t-banks .linkish"), spec.fw_banks.bank_ids.length);
  check("every L2 request has an exchange to link to",
    spec.l2_requests.every((r) =>
      spec.exchanges.some((e) => e.request_id === r.id)), true);

  const handshake = [...d.querySelectorAll("#t-l2 .linkish")]
    .find((b) => b.textContent === "HANDSHAKE");
  if (handshake) {
    handshake.click();
    check("clicking a request opens Try it", d.getElementById("tab-try").hidden, false);
    check("clicking a request selects its exchange",
      /Handshake/.test(d.getElementById("try-pick").value), true);
  }

  // the boot toggles go through the same shared helper
  const fwNo = [...d.querySelectorAll("#seg-fw button")].find((b) => b.textContent === "no");
  if (fwNo) {
    fwNo.click();
    check("boot toggle marks itself pressed", fwNo.getAttribute("aria-pressed"), "true");
    check("boot toggle redraws the action buttons",
      d.querySelectorAll("#acts button").length > 0, true);
  }

  // the walkthrough must step through the captured trace, not a description
  {
    const W = spec.walkthroughs;
    // The trace follows the Try-it picker: whatever request and mode are shown.
    const shownKey = d.getElementById("try-pick").value;
    const shownMode = [...d.querySelectorAll("#try-mode button")].find((b) => b.getAttribute("aria-pressed") === "true").textContent;
    const sc = W.scenarios.find((x) => x.mode === shownMode && x.group + " · " + x.label === shownKey);
    check("a trace exists for the request Try it is showing", !!sc, true);
    check("walkthrough renders every step of that trace",
      d.querySelectorAll("#walk-steps .wstep").length, sc.steps.length);
    const cur = () => [...d.querySelectorAll("#walk-steps .wstep")].findIndex((r) => r.classList.contains("cur"));
    check("walkthrough starts at step 1", cur(), 0);
    d.getElementById("walk-next").click(); d.getElementById("walk-next").click();
    check("next moves the highlighted step", cur(), 2);
    check("position readout follows", d.getElementById("walk-pos").textContent.startsWith("step 3 of"), true);
    check("source pane names the current function",
      d.getElementById("walk-src").textContent.includes(sc.steps[2].function), true);
    check("source pane lights the current line",
      d.querySelectorAll("#walk-src .srcline.cur").length, 1);
    d.getElementById("walk-run").click();
    check("run to end lands on the last step", cur(), sc.steps.length - 1);
    // no reset button: play from the last step restarts at the first
    d.getElementById("walk-play").click();
    check("play from the end restarts at the first step", cur() <= 1, true);
    d.getElementById("walk-play").click();   // pause again (back is disabled at step 1)
    check("play toggles back to play when paused", d.getElementById("walk-play").textContent.includes("play"), true);
    d.getElementById("walk-next").click(); d.getElementById("walk-back").click(); d.getElementById("walk-back").click();
    check("back stops at the first step", cur(), 0);
    // play advances on its own at the picked pace, and a manual step stops it
    const speed = d.getElementById("walk-speed"); speed.value = "250";
    d.getElementById("walk-play").click();
    check("play button reads pause while playing", d.getElementById("walk-play").textContent.includes("pause"), true);
    // Wait for the ticks rather than a fixed time: under load two 250 ms
    // ticks were once observed as one in 650 ms.
    const t0 = Date.now();
    while (cur() < 2 && Date.now() - t0 < 5000) await new Promise((r) => setTimeout(r, 25));
    check("play advanced two steps on its own", cur(), 2);
    d.getElementById("walk-back").click();
    check("a manual step stops play", d.getElementById("walk-play").textContent.includes("play"), true);
    const at = cur();
    await new Promise((r) => setTimeout(r, 400));
    check("nothing moves after play is stopped", cur(), at);
    // changing the Try-it request must rebuild the trace for THAT request
    const pick = d.getElementById("try-pick");
    const other = [...pick.options].find((o) => o.value !== shownKey);
    pick.value = other.value; pick.dispatchEvent(new dom.window.Event("change"));
    const sc2 = W.scenarios.find((x) => x.mode === shownMode && x.group + " · " + x.label === other.value);
    check("changing the request rebuilds the step list",
      d.querySelectorAll("#walk-steps .wstep").length, sc2.steps.length);
    check("the trace note names the request class", d.getElementById("walk-note").textContent.includes(sc2.request_class), true);
  }

  // the boot table's status note is computed from the capture, not typed
  check("boot status note names UNKNOWN_REQ and links to Try it",
    d.getElementById("boot-status-note").textContent.includes("UNKNOWN_REQ") &&
    d.querySelectorAll("#boot-status-note button.linkish").length === 1, true);

  check("six tabs", n("#tabs button"), 6);
  // The LIVE badge once painted while hidden: .tag's display beat the UA
  // [hidden] rule. Check the computed style, not the attribute.
  check("hidden elements do not paint",
    dom.window.getComputedStyle(d.getElementById("live-badge")).display, "none");
  check("how-it-works is a collapsible under the header", !!d.querySelector("header details#about-box #about"), true);
  check("errors after interaction", errors.length, 0);

  console.log();
  if (failures.length) {
    console.error(`${failures.length} failed: ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log("all checks passed");
  process.exit(0);   // jsdom timers would otherwise keep the process alive
}
