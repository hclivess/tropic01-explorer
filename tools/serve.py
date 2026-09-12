#!/usr/bin/env python3
"""Serve the explorer with a *live* model behind it.

    PYTHONPATH=/path/to/ts-tvl python3 tools/serve.py
    → http://127.0.0.1:8800

The published page at hclivess.github.io is static, and it has to be: a browser
cannot open a raw TCP socket, and `model_server` listens on the machine running
it, not on GitHub's. So the page ships with captured exchanges and plays them
back.

This script is the other half. It starts the **real** `model_server` over TCP,
connects ts-tvl's own `TCPTropicProtocol` to it, and serves the same page with a
small HTTP API in front. The page probes for that API at load: if it answers,
the Try-it tab stops replaying and starts sending. Same page, same markup - the
only difference is whether the bytes come from a capture or from a model that is
running right now.

Nothing about the protocol is reimplemented here. `Host` binds to
`TCPTropicProtocol` exactly as it binds to `Tropic01Model`, because the server
client implements the same interface the model does; this file only moves bytes
between HTTP and that object.

Endpoints:
    GET  /api/health       is a model attached, powered, and in which mode
    POST /api/l2           {"request": "<hex>"} -> raw response bytes
    POST /api/power_on     power the chip on (and boot it)
    POST /api/power_off    power the chip off - subsequent requests will fail
    GET  /api/chip_status  the CHIP_STATUS byte, read the way libtropic reads it
"""

from __future__ import annotations

import argparse
import atexit
import json
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Chip:
    """A `model_server` process plus a Host talking to it, behind a lock."""

    def __init__(self, port: int, config: Optional[pathlib.Path]) -> None:
        from tvl.host.host import Host
        from tvl.server.tcp_client import TCPTropicProtocol

        if (server := shutil.which("model_server")) is None:
            raise SystemExit(
                "model_server is not on PATH. It is a console script installed "
                "with ts-tvl:\n"
                "  python3 -m venv .venv && .venv/bin/pip install -e /path/to/ts-tvl\n"
                "  PATH=$PWD/.venv/bin:$PATH PYTHONPATH=/path/to/ts-tvl "
                "python3 tools/serve.py"
            )

        command = [server, "tcp", "--port", str(port)]
        if config is not None:
            command += ["--configuration", str(config)]
        print(f"  starting: {' '.join(command)}")
        self.process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        atexit.register(self.stop)
        # `atexit` does not run on SIGTERM, so a `kill` leaves model_server
        # orphaned - holding its port, and its parent's pipes. This is exactly
        # the defect recorded against model_runner.py in BACKLOG 1.2, and this
        # script had it too until a stray `kill` left two servers running.
        for sig in (signal.SIGTERM, signal.SIGHUP):
            try:
                previous = signal.getsignal(sig)
                signal.signal(sig, partial(self._on_signal, previous))
            except (ValueError, OSError):
                pass  # not the main thread, or the platform lacks it

        # The server binds its socket only once the model is ready - deliberately,
        # since TR01SV-98 - so a connection refused here means "not yet", not
        # "broken". Retry rather than racing it.
        deadline = time.monotonic() + 15
        last: Optional[Exception] = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise SystemExit(
                    f"model_server exited with {self.process.returncode} before "
                    f"accepting a connection."
                )
            try:
                self.target = TCPTropicProtocol(port=port)
                self.target.connect()
                break
            except Exception as exc:  # noqa: BLE001 - report whatever it was
                last, _ = exc, time.sleep(0.2)
        else:
            self.stop()
            raise SystemExit(f"could not reach model_server on {port}: {last}")

        self.host = Host().set_target(self.target)
        self.target.power_on()
        self.powered = True
        self.lock = threading.Lock()
        print(f"  model_server ready on 127.0.0.1:{port}")

    def chip_status(self) -> int:
        """CHIP_STATUS, read the way libtropic's lt_get_tr01_mode() reads it."""
        from tvl.constants import L2IdFieldEnum

        self.target.spi_drive_csn_low()
        tx = self.target.spi_send(bytes([L2IdFieldEnum.GET_RESP]) + bytes(4))
        self.target.spi_drive_csn_high()
        return tx[0]

    def send(self, raw: bytes) -> bytes:
        return bytes(self.host.send_request(raw))

    def power(self, on: bool) -> None:
        """Power the chip on or off.

        Off is not a pause: it is the model's `power_off`, which drops all
        volatile state. Whatever the chip was in the middle of is gone, and that
        is the point of having the button.
        """
        if on:
            self.target.power_on()
        else:
            self.target.power_off()
        self.powered = on

    def status(self) -> Dict[str, Any]:
        from tvl.constants import L1ChipStatusFlag

        if not self.powered:
            return {"live": True, "powered": False, "chip_status": None,
                    "mode": None}
        chip_status = self.chip_status()
        return {
            "live": True,
            "powered": True,
            "chip_status": chip_status,
            "mode": "START_UP" if chip_status & L1ChipStatusFlag.START
            else "APPLICATION",
        }

    def _on_signal(self, previous: Any, signum: int, frame: Any) -> None:
        self.stop()
        if callable(previous) and previous not in (signal.SIG_IGN, signal.SIG_DFL):
            previous(signum, frame)
        else:
            signal.signal(signum, signal.SIG_DFL)
            signal.raise_signal(signum)

    def stop(self) -> None:
        for close in (getattr(self, "target", None), None):
            try:
                if close is not None:
                    close.disconnect()
            except Exception:  # noqa: BLE001 - shutting down regardless
                pass
        process = getattr(self, "process", None)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


class Handler(SimpleHTTPRequestHandler):
    chip: Chip

    def log_message(self, *args: Any) -> None:  # quieter than the default
        pass

    #: Origins allowed to drive this bridge. Loopback is exempt from browsers'
    #: mixed-content blocking - it counts as a trustworthy origin - so the
    #: page served from GitHub Pages *can* reach a bridge running here, as long
    #: as the bridge says it may. Narrow by default; --allow-origin widens it.
    allow_origin: str = "https://hclivess.github.io"

    def _cors(self) -> None:
        origin = self.headers.get("Origin")
        if origin and (self.allow_origin == "*" or origin == self.allow_origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server's naming
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, payload: Dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        if self.path == "/api/health":
            with self.chip.lock:
                self._json(self.chip.status())
            return
        if self.path == "/api/chip_status":
            with self.chip.lock:
                self._json({"chip_status": self.chip.chip_status()})
            return
        super().do_GET()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            self._json({"error": f"bad JSON: {exc}"}, 400)
            return

        if self.path in ("/api/power_on", "/api/power_off"):
            with self.chip.lock:
                self.chip.power(self.path.endswith("_on"))
                self._json(self.chip.status())
            return

        if self.path == "/api/l2":
            try:
                raw = bytes.fromhex(payload.get("request", ""))
            except ValueError as exc:
                self._json({"error": f"bad hex: {exc}"}, 400)
                return
            if not raw:
                self._json({"error": "empty request"}, 400)
                return
            if not self.chip.powered:
                self._json({"error": "the chip is powered off"}, 409)
                return
            try:
                with self.chip.lock:
                    response = self.chip.send(raw)
                    status = self.chip.chip_status()
            except Exception as exc:  # noqa: BLE001 - surface it to the page
                self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
                return
            self._json(
                {
                    "request": raw.hex(),
                    "response": response.hex(),
                    "chip_status_after": status,
                }
            )
            return

        self._json({"error": "no such endpoint"}, 404)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8800, help="HTTP port")
    parser.add_argument("--model-port", type=int, default=0,
                        help="TCP port for model_server (default: a free one)")
    parser.add_argument("--config", type=pathlib.Path, default=None,
                        help="model configuration YAML")
    parser.add_argument("--allow-origin", default=Handler.allow_origin,
                        help="origin permitted to drive this bridge from a "
                             "browser; '*' allows any. Defaults to the "
                             "published page.")
    args = parser.parse_args()

    try:
        import tvl  # noqa: F401
    except ImportError:
        raise SystemExit(
            "ts-tvl is not importable. Run with:\n"
            "  PYTHONPATH=/path/to/ts-tvl python3 tools/serve.py"
        ) from None

    # Never the default 28992: that port is shared with ctest's model_runner and
    # ts-tvl's own TCP tests, and a collision does not error - it silently
    # serves the wrong client. See BACKLOG 1.1.
    model_port = args.model_port or free_port()
    print("TROPIC01 Explorer — live mode")
    chip = Chip(model_port, args.config)

    Handler.chip = chip
    Handler.allow_origin = args.allow_origin
    handler = partial(Handler, directory=str(DOCS))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"\n  http://127.0.0.1:{args.port}\n")
    print("  The page will detect the API and switch the Try-it tab from")
    print("  replaying captured bytes to sending them to this model.")
    print(f"\n  The published page can drive it too - {args.allow_origin}")
    print("  is permitted, and loopback is exempt from mixed-content blocking.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
        chip.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
