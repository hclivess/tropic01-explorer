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
`_HEADER_STRUCT`. Field descriptions come from the source through `ast`, because
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

**3. Enforcement.** CI runs the generator with `--check`, which regenerates in
memory and fails if `docs/model_spec.js` differs. Drift is therefore a red
build, not a thing someone notices later.

```
ts-tvl (Python)
   │
   │  introspect  ──  registers, fields, ids, tables, struct layout
   │  execute     ──  boot transitions, wire traces
   ▼
docs/model_spec.js        ← generated, never edited
   │
   ▼
docs/index.html           ← renders it, computes nothing
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
npm install jsdom
node tools/render_test.js
```

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
