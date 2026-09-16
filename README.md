# TROPIC01 Explorer

An interactive view of the [ts-tvl](https://github.com/tropicsquare/ts-tvl)
functional model of the TROPIC01 secure element. Live at
<https://hclivess.github.io/tropic01-explorer/>, or open `docs/index.html` in a
browser: one file, no build, no network.

## What is on the page

| Tab | What it shows |
|---|---|
| **Boot** | The boot state machine as a captured table: every combination of starting mode, action, `MAINTENANCE_ENA` and whether a firmware bank is populated, and where the chip lands. The four CHIP_STATUS bits, which of them the model can set, and READY = 0 captured for real. |
| **Configuration & memory** | The 512-byte Configuration Object register by register, the memory partitions, and what a reboot clears. |
| **L2 / L3 API** | Which of the 8 L2 requests each firmware serves and why. The Get_Info objects per mode. The 52-byte firmware bank header. The 23 L3 commands with the register that gates each. |
| **Try it** | Every request sent in both modes against a fresh chip, byte by byte, with the same request in the other mode alongside. Under it, the same request traced through the model's code, and scripted sessions that chain requests. Deep links: `#try:<MODE>:<request>`. |
| **Examples** | A sixteen-step guided tour that sends real bytes and takes each reply apart, then ts-tvl's own `examples/` scripts run unmodified with their output and log. |
| **Constants** | Everything `tvl/constants.py` exports, read off the module. |

## Nothing on it is written by hand

`tools/generate_spec.py` produces `docs/model_spec.js`, and every value there
comes from one of two places:

- **Introspection** of the live objects: registers, field offsets, request ids,
  the gating tables, the header struct.
- **Execution** of the model: the boot table is the recorded outcome of running
  `_boot()` for every input; every byte in Try it and Examples was emitted by a
  real `Host` driving a real `Tropic01Model`, under pinned entropy so the
  capture reproduces.

The page renders that file and computes nothing. If the model changes, the
generator's `--check` mode fails, and the pre-push hook runs it:

```bash
git config core.hooksPath .githooks   # once per clone
```

## Regenerate, check, test

```bash
PYTHONPATH=/path/to/ts-tvl python3 tools/generate_spec.py --out docs/model_spec.js          # regenerate
PYTHONPATH=/path/to/ts-tvl python3 tools/generate_spec.py --out docs/model_spec.js --check  # verify only
npm install --no-save jsdom && node tools/render_test.js                                     # the page shows every item in the spec
tools/check.sh [path-to-ts-tvl]                                                              # both, what the hook runs
```

The capture is deterministic because three things that float by default are
pinned: `busy_iter=[False]`, the model's RNG, and the X25519 keypairs. The
tell that it worked: two handshakes in one capture produce identical bytes.

## Live mode

The published page plays back captured bytes; a browser cannot open a TCP
socket. `tools/serve.py` starts a real `model_server`, connects ts-tvl's own
`TCPTropicProtocol` to it, and serves the page with a small HTTP API in front.
The page detects it, shows a LIVE badge, and Try it gains a "send for real"
button that compares the live answer with the captured one.

```bash
python3 -m venv .venv && .venv/bin/pip install -e /path/to/ts-tvl
PATH=$PWD/.venv/bin:$PATH PYTHONPATH=/path/to/ts-tvl python3 tools/serve.py   # → http://127.0.0.1:8800
node tools/live_test.js http://127.0.0.1:8800
```

It picks a free port rather than 28992, which is shared with ctest's
`model_runner` and ts-tvl's TCP tests, and whose collisions do not error.

## Layout

```
docs/index.html          the page
docs/model_spec.js       GENERATED; everything the page knows
tools/generate_spec.py   the generator
tools/tour.py            the guided tour's steps
tools/serve.py           live mode
tools/render_test.js     headless render assertions
tools/live_test.js       live-mode assertions
tools/check.sh           the gates; run by .githooks/pre-push
```

## Limits

- **Application mode is corroborated; Start-up mode is not.** The application
  firmware is public and its L2 dispatcher agrees with the gating shown. The
  bootloader's sources are not, so the Start-up column shows what the model
  does, resting on the datasheet and libtropic's tests.
- **This shows the model, not the silicon.** Where they differ, the page shows
  the model being wrong, which is its job.
- The READY bit in captured rows reflects the SPI FSM at the moment of the read,
  so similar rows can differ by `0x01`. Captured, not idealised.
