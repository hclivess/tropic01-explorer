# TROPIC01 Explorer

An interactive view of the [ts-tvl](https://github.com/tropicsquare/ts-tvl)
functional model of the TROPIC01 secure element: the boot state machine, the
Configuration Object, which L2 requests each firmware answers, and real wire
traces.

Open `docs/index.html` in a browser. No build step, no dependencies, no network.

---

## The point: it cannot drift

A visualiser that restates what the code does is a second implementation, and
second implementations rot. Six months later the diagram is confidently wrong,
which is worse than having no diagram.

So nothing on the page is written by hand. `tools/generate_spec.py` produces
`docs/model_spec.js`, and it obtains every value in one of exactly two ways.

**1. Introspection of the live objects.** Registers, field offsets and widths,
request ids, the gating tables, the FW bank header layout — read off
`ConfigurationObjectImpl`, `L2Enum`, `L2_REQUEST_MODES`, `GET_INFO_OBJECTS`,
`_HEADER`. Field descriptions come from the source through `ast`, because
Python discards the string literals that document attributes.

The header layout is a good example of why this matters. The generator does not
restate the 52-byte layout; it parses the model's own `struct` format string and
derives the offsets, then displays the derived total next to the declared
`FW_HEADER_SIZE`. If those two ever disagree the page says so on its face.

**2. Execution of the model.** The boot table is not a description of `_boot()`.
It is the recorded outcome of running `_boot()` for every combination of
starting mode, action, `CFG_START_UP.MAINTENANCE_ENA` and whether a RISC-V FW
bank is populated. The GUI looks answers up in it. There is no JavaScript
reimplementation of the state machine to disagree with the Python one.

Likewise the wire traces are bytes a real model really emitted, captured by
driving a real `Host` against a real `Tropic01Model`.

The **Examples** tab runs ts-tvl's own `examples/` scripts unmodified and shows,
for each: its source, its `stdout`, and **its full log stream** — 43 to 236 lines
per script of the model and host narrating the protocol to each other. Every one
of the four calls `setup_logging()`, so every one has a log; showing only what a
script `print`s would hide most of what it does.

Capturing the log needed two things beyond hooking the send path. `dictConfig`
defaults to `disable_existing_loggers=True` and `logging.getLogger("host")` is
the same object every run, so the second capture onwards was silent until the
loggers are re-enabled per run. And CPython object reprs carry a memory address,
which was the last thing differing between invocations once the entropy was
pinned — scrubbed narrowly at the `... at 0x...>` form so real hex in the logs is
untouched.

The **Try it** tab is the same idea taken as far as it goes: every request worth
sending, sent in every mode, each against a *fresh* chip so nothing leaks
between them. 48 exchanges. Picking one shows what the model actually answered
and what the *other* firmware answers to the identical bytes — which is the
quickest way to see the shape of the change:

| request | Application | Start-up |
|---|---|---|
| `Get_Info(FW_BANK)` | `0x7F GEN_ERR` | `0x01 REQ_OK` |
| `Handshake_Req` | `0x01 REQ_OK` | `0x7E UNKNOWN_REQ` |
| `Sleep_Req` | `0x01 REQ_OK` | `0x7E UNKNOWN_REQ` |
| `Get_Info(CHIP_ID)` | `0x01` — byte-identical | `0x01` — byte-identical |

None of that table is typed here by a person either; it is what the capture
came back with.

Below the bytes, **How the code got there** is the same exchange traced: every
request in the list — 24 in both modes, a `Startup_Req` followed by the read
that lands the restart, the two CO-gated refusals with the R-config that clears
their bit — was recorded with `sys.settrace` while it went through the model.
Pick a request above and step through its calls; the source of the function at
the cursor lights up at the executing line. Only the model's own files are
traced — the pydantic and protocol plumbing is filtered out, or the reboot
scenario would be four hundred steps of register reads.

**All layers.** The same list carries **L3**: every one of the 23 commands sent
for real inside a secure session on one chip, in an order where each finds the
state the previous one left (a key generated, then read, then used to sign), plus
two refusals on chips whose R-config forbids them. For each you get the plaintext
command and result, the `Encrypted_Cmd` frames that carried them, and — for every
exchange at every layer — the **L1** view: each chip-select transaction, MOSI and
MISO, with the CHIP_STATUS byte decoded. The **L2 / L3 API** tab lists the
command set with the Configuration Object register that gates each, read off the
handlers' source; **Configuration & memory** adds the partitions — slot counts
derived from the UAP registers' field names, sizes from the partition modules —
and what a reboot clears.

**3. Enforcement.** The generator's `--check` mode regenerates in memory and
fails if `docs/model_spec.js` differs. That gate runs **before every push**:

```bash
git config core.hooksPath .githooks   # once per clone
```

It runs locally rather than in CI on purpose. Regenerating requires a ts-tvl
checkout, which is private; a workflow in this public repo would need a secret
with read access to it, and a public repo's workflows are a poor place to keep
one. Locally the same check costs nothing and has no blast radius. `--no-verify`
bypasses it, which should show up in the commit message.

CI still runs the render test on every push, and the `spec-is-current` job is
written and ready — set the `TS_TVL_REPO` variable and a read-only
`TS_TVL_TOKEN` secret and it arms itself. Until then it emits a warning rather
than passing quietly.

```
ts-tvl (Python)
   │
   │  introspect  ──  registers, fields, ids, tables, struct layout
   │  execute     ──  boot transitions, wire traces, call traces,
   │                  every L3 command in a session, SPI transactions
   ▼
docs/model_spec.js        ← generated, never edited
   │
   ▼
docs/index.html           ← renders it, computes nothing
```

## Live mode — a real model behind the page

The published page is static and must be: a browser cannot open a raw TCP
socket, and `model_server` listens on whatever machine is running it, not on
GitHub's. So the page plays back captured bytes.

`tools/serve.py` is the other half. It starts the **real** `model_server` over
TCP, connects ts-tvl's own `TCPTropicProtocol` to it, and serves the same page
with a small HTTP API in front:

```bash
python3 -m venv .venv && .venv/bin/pip install -e /path/to/ts-tvl
PATH=$PWD/.venv/bin:$PATH PYTHONPATH=/path/to/ts-tvl python3 tools/serve.py
# → http://127.0.0.1:8800
```

The page probes for that API at load. If it answers, a **LIVE** badge appears and
the Try-it tab grows two buttons: *send this request for real* and a power
toggle. Sending puts the bytes through a model that is running now, and
compares the answer with the captured one — agreement means the capture still
describes the model.

Nothing about the protocol is reimplemented in the bridge. `Host` binds to
`TCPTropicProtocol` exactly as it binds to `Tropic01Model`, because the TCP
client implements the same interface the model does; `serve.py` only moves bytes
between HTTP and that object. It also picks a free port rather than the default
28992, which is shared with ctest's `model_runner` and ts-tvl's own TCP tests and
whose collisions do not error — they silently serve the wrong client.

**Power off is not a pause.** It is the model's `power_off`, which drops all
volatile state: the session, the buffers, and the latched configuration.

```bash
node tools/live_test.js http://127.0.0.1:8800   # asserts the live half
EXPLORER_LIVE_URL=http://127.0.0.1:8800 tools/check.sh   # all three gates
```

## Regenerating

```bash
PYTHONPATH=/path/to/ts-tvl python3 tools/generate_spec.py --out docs/model_spec.js
```

Verify instead of writing:

```bash
PYTHONPATH=/path/to/ts-tvl python3 tools/generate_spec.py --out docs/model_spec.js --check
```

### Determinism

The capture must be byte-reproducible or `--check` fails on unchanged code.
Three things float by default and are pinned:

| | why |
|---|---|
| `busy_iter=[False]` | defaults to a **randomly shuffled** sequence (`spi_fsm.py:40`) that lands in the READY bit of `CHIP_STATUS`. It belongs to the SPI FSM and is only settable at construction — assigning `model.busy_iter` afterwards does nothing |
| `debug_random_value=bytes(4)` | pins the model's RNG |
| fixed X25519 keypairs | a bare model is unprovisioned, and handshakes must reproduce |

The tell that it worked: two handshakes in one capture produce identical bytes.
On silicon that would be alarming; here it is the proof that nothing is
floating.

## Testing

```bash
npm install --no-save jsdom
tools/check.sh [path-to-ts-tvl]     # both gates; what the pre-push hook runs
node tools/render_test.js           # just the render assertions
```

`check.sh` finds ts-tvl at `../ts-tvl`, or `$TS_TVL`, or the path you give it.
If it cannot find one it **says the check was skipped** rather than passing
silently - an anti-drift gate that quietly does nothing is worse than none.

The render test loads the page in a headless DOM and asserts that every item in
the spec reaches the screen — **counts derived from the spec, not hard-coded**.
Add a register to the model and it still passes; stop rendering one and it
fails. It also drives the boot panel and checks the result against the captured
table, so the interactive part is covered too.

## Layout

```
docs/index.html        the page — single file, no CDN, works from file://
docs/model_spec.js     GENERATED. everything the page knows
tools/generate_spec.py the generator — introspects and executes ts-tvl
tools/render_test.js   headless render assertions
tools/check.sh         both gates, run by the pre-push hook
.githooks/pre-push     refuses to push a page that no longer matches the model
```

`model_spec.js` is JavaScript rather than JSON so the page works from a plain
`file://` URL: `fetch()` of a sibling `.json` is blocked by CORS there, a
`<script src>` is not. The body is still readable JSON.

## Limits, stated plainly

- **Application mode is corroborated; Start-up mode is not.** The application
  firmware is public (`tropicsquare/ts-tr01-app`) and its L2 dispatcher agrees
  with the gating shown here. The bootloader's sources are not public, so the
  Start-up column reflects what the *model* does, which rests on the datasheet
  and on libtropic's expectations.
- **This shows the model, not the silicon.** Where the two differ, the page will
  faithfully show the model being wrong. That is the correct behaviour for a
  tool whose job is to make the model legible.
- The `CHIP_STATUS` READY bit in the captured table reflects SPI FSM state at
  the moment of the read, which is why otherwise-similar rows can differ by
  `0x01`. It is captured rather than idealised.
