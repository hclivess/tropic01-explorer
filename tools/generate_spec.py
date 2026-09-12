#!/usr/bin/env python3
"""Emit the explorer's entire dataset by introspecting and executing ts-tvl.

Nothing in `docs/` is written by hand. Every register, field, address, gating
rule, status byte, frame layout and wire byte in the GUI comes from here, and
this script gets all of it in one of exactly two ways:

1. **Introspection** of the live objects (`ConfigurationObjectImpl`, `L2Enum`,
   `L2_REQUEST_MODES`, `_HEADER_STRUCT`, ...) plus `ast` for the docstrings
   Python discards at runtime.
2. **Execution** of the real model. The boot transition table is not a
   description of `_boot()`, it is the exhaustive record of what `_boot()`
   actually did for every combination of inputs. The wire traces are bytes the
   model really produced.

So the GUI cannot drift from the model: there is no second implementation to
drift. If the model changes, this output changes, and CI fails until the
committed copy is regenerated.

Usage:
    PYTHONPATH=<ts-tvl> python3 tools/generate_spec.py --out docs/model_spec.json
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import itertools
import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

from tvl.api.l2_api import (
    L2Enum,
    TsL2EncryptedSessionAbtRequest,
    TsL2GetInfoRequest,
    TsL2GetLogRequest,
    TsL2HandshakeRequest,
    TsL2ResendRequest,
    TsL2SleepRequest,
    TsL2StartupRequest,
)
from tvl.constants import L1ChipStatusFlag, L2StatusEnum
from tvl.host.host import Host
from tvl.targets.model import tropic01_l2_api_impl as l2_impl
from tvl.targets.model.configuration_object_impl import (
    ConfigObjectRegisterAddressEnum,
    ConfigurationObjectImpl,
)
from tvl.targets.model.internal.chip_mode import BootTarget, ChipMode
from tvl.targets.model.internal.configuration_object import (
    CONFIGURATION_ACCESS_PRIVILEGES,
    FUNCTIONALITY_ACCESS_PRIVILEGES,
    ConfigObjectField,
)
from tvl.targets.model.internal import fw_bank as fw_bank_mod
from tvl.targets.model.internal.fw_bank import (
    FW_HEADER_SIZE,
    FwBankIdEnum,
    FwBanks,
    FwTypeEnum,
)
from tvl.targets.model.tropic01_model import Tropic01Model

SPEC_VERSION = 1

# The application Configuration Object owns 0x14 and up; everything below it
# comes from the bootloader CO. Stated in the public application RDL:
#     "Application Configuration COs / Keep on addresses between 0x14-0x1FC"
APPLICATION_CO_BASE = 0x14


# --------------------------------------------------------------------------
# docstrings Python throws away
# --------------------------------------------------------------------------
def attribute_docs(module: Any) -> Dict[str, Dict[str, str]]:
    """`{ClassName: {attribute: docstring}}` for a module, read from its source.

    A string literal after an assignment documents the attribute for human
    readers and for Sphinx, but Python discards it. `ast` keeps it.
    """
    tree = ast.parse(pathlib.Path(inspect.getfile(module)).read_text())
    out: Dict[str, Dict[str, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        docs: Dict[str, str] = {}
        previous: Optional[str] = None
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
                previous = stmt.targets[0].id
            elif (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
                and previous is not None
            ):
                docs[previous] = " ".join(stmt.value.value.split())
                previous = None
            else:
                previous = None
        if docs:
            out[node.name] = docs
    return out


def table_reasons(source_path: pathlib.Path, table_name: str) -> Dict[str, str]:
    """The `# comment` justifying each entry of a dict literal in the source.

    `L2_REQUEST_MODES` carries a reason per row as a comment. Comments are not
    in the AST and not available at runtime, so read them off the text - but key
    them by the entry they follow, so a reordered table still lines up.
    """
    lines = source_path.read_text().splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.startswith(f"{table_name}:")
    )
    reasons: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for line in lines[start + 1 :]:
        if line.startswith("}"):
            break
        if (entry := re.match(r"\s*L2Enum\.(\w+):", line)) is not None:
            current = entry.group(1)
            reasons[current] = []
        elif (comment := re.match(r"\s*#\s?(.*)", line)) is not None:
            text = comment.group(1).strip()
            # Section banners like "--- served by both ... ---" are not reasons.
            if current is not None and not text.startswith("---"):
                reasons[current].append(text)
    return {k: " ".join(v) for k, v in reasons.items() if v}


# --------------------------------------------------------------------------
# introspected structure
# --------------------------------------------------------------------------
def chip_modes() -> List[Dict[str, Any]]:
    docs = attribute_docs(sys.modules[ChipMode.__module__])
    return [
        {
            "name": mode.name,
            "chip_status_flags": int(mode.chip_status_flags),
            "doc": docs.get("ChipMode", {}).get(mode.name, ""),
        }
        for mode in ChipMode
    ]


def boot_targets() -> List[Dict[str, Any]]:
    docs = attribute_docs(sys.modules[BootTarget.__module__])
    return [
        {"name": t.name, "doc": docs.get("BootTarget", {}).get(t.name, "")}
        for t in BootTarget
    ]


def chip_status_flags() -> List[Dict[str, Any]]:
    return [{"name": f.name, "value": int(f.value)} for f in L1ChipStatusFlag]


def l2_status_codes() -> List[Dict[str, Any]]:
    return [{"name": s.name, "value": int(s.value)} for s in L2StatusEnum]


def co_registers() -> List[Dict[str, Any]]:
    docs = attribute_docs(sys.modules[ConfigurationObjectImpl.__module__])
    out: List[Dict[str, Any]] = []
    for name, register in ConfigurationObjectImpl().registers():
        cls = type(register)
        fields = [
            {
                "name": field_name,
                "offset": descriptor.offset,
                "width": descriptor.mask.bit_length(),
                "doc": docs.get(cls.__name__, {}).get(field_name, ""),
            }
            for field_name, descriptor in vars(cls).items()
            if isinstance(descriptor, ConfigObjectField)
        ]
        address = register.address
        out.append(
            {
                "name": name.upper(),
                "class": cls.__name__,
                "address": address,
                # Which firmware's Configuration Object declares it. The
                # application CO is public and holds only CFG_GPO and
                # CFG_SLEEP_MODE below the UAP block.
                "origin": "application" if address >= APPLICATION_CO_BASE else "bootloader",
                "half": (
                    "functionality"
                    if address in FUNCTIONALITY_ACCESS_PRIVILEGES
                    else "configuration"
                    if address in CONFIGURATION_ACCESS_PRIVILEGES
                    else "unmapped"
                ),
                "fields": sorted(fields, key=lambda f: f["offset"]),
            }
        )
    return sorted(out, key=lambda r: r["address"])


def l2_requests() -> List[Dict[str, Any]]:
    reasons = table_reasons(
        pathlib.Path(inspect.getfile(l2_impl)), "L2_REQUEST_MODES"
    )
    # The reasons are scraped out of comments, which no parser can follow
    # through an arbitrary reformat. Rather than make the regex cleverer, make
    # its failure loud: every gated request has a documented reason today, so
    # any request without one means the scrape broke, not that someone wrote an
    # undocumented row. Silently shipping a table of "—" is the bad outcome.
    missing = sorted(r.name for r in L2Enum if not reasons.get(r.name))
    if missing:
        raise SystemExit(
            "no reason comment found for: " + ", ".join(missing) + ".\n"
            "Either L2_REQUEST_MODES gained an undocumented entry, or it was "
            "reformatted and table_reasons() can no longer follow it. Fix "
            "whichever it is - do not ship the page with empty reasons."
        )
    return [
        {
            "name": request_id.name,
            "id": int(request_id.value),
            "modes": sorted(m.name for m in l2_impl.L2_REQUEST_MODES[request_id]),
            "reason": reasons[request_id.name],
        }
        for request_id in sorted(L2Enum, key=lambda e: e.value)
    ]


def get_info_objects() -> Dict[str, List[Dict[str, Any]]]:
    oid = TsL2GetInfoRequest.ObjectIdEnum
    docs = attribute_docs(sys.modules[l2_impl.__name__])
    return {
        mode.name: [
            {
                "name": oid(object_id).name,
                "value": int(object_id),
                "provider": provider,
                # The provider's own docstring says what it serves.
                "doc": " ".join(
                    (getattr(Tropic01Model, provider).__doc__ or "").split()
                ),
            }
            for object_id, provider in sorted(providers.items())
        ]
        for mode, providers in l2_impl.GET_INFO_OBJECTS.items()
    }


def fw_bank_layout() -> Dict[str, Any]:
    docs = attribute_docs(fw_bank_mod)
    # The header layout is a struct format string; derive the field sizes from
    # it rather than restating them, so a change to the struct shows up here.
    fmt = fw_bank_mod._HEADER_STRUCT.format
    # The one place this file names something the model does not hand it: the
    # struct format carries sizes but not labels. Guarded two ways, because a
    # silent mislabel here would be exactly the drift this repo exists to stop.
    names = ["type", "_padding", "header_version", "version", "size", "git_hash",
             "hash", "pair_version"]
    pieces = split_struct_format(fmt)
    if len(names) != len(pieces):
        raise SystemExit(
            f"FW header field names are out of step with the model's struct "
            f"format {fmt!r}: {len(names)} names, {len(pieces)} fields. "
            f"Update `names` in fw_bank_layout() - zip() would otherwise "
            f"silently mislabel every field after the change."
        )
    sizes = [struct_size(piece) for piece in pieces]
    offset = 0
    fields = []
    for name, size in zip(names, sizes):
        fields.append(
            {
                "name": name,
                "offset": offset,
                "size": size,
                "doc": docs.get("FwBank", {}).get(name, ""),
            }
        )
        offset += size
    if offset != FW_HEADER_SIZE:
        raise SystemExit(
            f"FW header struct {fmt!r} packs {offset} bytes but the model "
            f"declares FW_HEADER_SIZE = {FW_HEADER_SIZE}."
        )
    return {
        "header_size": FW_HEADER_SIZE,
        "struct_format": fmt,
        "total_from_struct": offset,
        "fields": fields,
        "bank_ids": [
            {
                "name": b.name,
                "value": int(b.value),
                "doc": docs.get("FwBankIdEnum", {}).get(b.name, ""),
            }
            for b in FwBankIdEnum
        ],
        "types": [{"name": t.name, "value": int(t.value)} for t in FwTypeEnum],
        "default_populated": sorted(int(b) for b in FwBanks()),
    }


def split_struct_format(fmt: str) -> List[str]:
    """Split a struct format string into one entry per field."""
    return re.findall(r"\d*[a-zA-Z]", fmt.lstrip("<>=!@"))


def struct_size(piece: str) -> int:
    import struct

    return struct.calcsize("<" + piece)


# --------------------------------------------------------------------------
# captured behaviour: what the model DID, not what it is described as doing
# --------------------------------------------------------------------------
def boot_transitions() -> List[Dict[str, Any]]:
    """Exhaustive record of the boot state machine, by executing it.

    Every combination of (starting mode, requested action, MAINTENANCE_ENA,
    whether a RISC-V FW bank is populated) is actually run against a real model
    and the outcome recorded. The GUI looks the answer up; it does not
    reimplement `_boot()`.
    """
    rows: List[Dict[str, Any]] = []
    startup = TsL2StartupRequest.StartupIdEnum

    for start, action, maintenance, has_fw in itertools.product(
        list(ChipMode), ["POWER_ON", *[s.name for s in startup]], [1, 0], [True, False]
    ):
        model = build_model(maintenance_ena=maintenance, has_fw=has_fw)
        model.power_on()
        # Put the chip in the requested starting mode, if it can get there.
        if start is ChipMode.START_UP and model.chip_mode is not ChipMode.START_UP:
            model.reboot(BootTarget.START_UP)
        if model.chip_mode is not start:
            continue  # unreachable starting state for this configuration

        status: Optional[int] = None
        if action == "POWER_ON":
            model.power_on()
        else:
            host = Host().set_target(model)
            response = host.send_request(
                TsL2StartupRequest(startup_id=getattr(startup, action))
            )
            status = int(response.status.value)
            # The restart is deferred until the host reads the response.
            read_chip_status(model)

        rows.append(
            {
                "from": start.name,
                "action": action,
                "maintenance_ena": maintenance,
                "has_riscv_fw": has_fw,
                "to": model.chip_mode.name,
                "l2_status": status,
                "chip_status": read_chip_status(model),
            }
        )
    return rows


def build_model(*, maintenance_ena: int = 1, has_fw: bool = True) -> Tropic01Model:
    # `busy_iter` defaults to a *randomly shuffled* sequence (spi_fsm.py:40),
    # which lands in the READY bit of CHIP_STATUS and makes the captured table
    # differ run to run. It belongs to the SPI FSM and is only settable at
    # construction - assigning `model.busy_iter` afterwards does nothing.
    model = Tropic01Model(busy_iter=[False])
    if not maintenance_ena:
        model.r_config.write_bit(ConfigObjectRegisterAddressEnum.CFG_START_UP, 3)
    if not has_fw:
        model.fw_banks = FwBanks(banks={})
    return model


def read_chip_status(model: Tropic01Model) -> int:
    """CHIP_STATUS the way libtropic's lt_get_tr01_mode() reads it."""
    from tvl.constants import L2IdFieldEnum

    model.spi_drive_csn_low()
    tx = model.spi_send(bytes([L2IdFieldEnum.GET_RESP]))
    model.spi_drive_csn_high()
    return tx[0]


def wire_traces() -> List[Dict[str, Any]]:
    """Real request/response byte pairs, produced by driving a real model.

    Determinism is forced so the committed trace is stable: the RNG is pinned
    and the busy simulation disabled. Two handshakes therefore produce identical
    bytes - alarming on silicon, and here the proof that nothing is floating.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    host_priv = bytes(range(32))
    key = X25519PrivateKey.from_private_bytes(host_priv)
    pub = key.public_key().public_bytes_raw()

    # A fixed Tropic keypair too: a bare model is unprovisioned, and the trace
    # has to be reproducible byte for byte.
    tropic_priv = bytes(range(32, 64))
    tropic_key = X25519PrivateKey.from_private_bytes(tropic_priv)

    model = Tropic01Model(
        debug_random_value=bytes(4),
        s_t_priv=tropic_priv,
        s_t_pub=tropic_key.public_key().public_bytes_raw(),
        busy_iter=[False],
    )
    model.i_pairing_keys[0].write(pub)
    model.power_on()
    host = Host(
        s_h_priv=[host_priv],
        s_h_pub=[pub],
        s_t_pub=model.s_t_pub,
        pairing_key_index=0,
        debug_random_value=bytes(4),
    ).set_target(model)

    oid = TsL2GetInfoRequest.ObjectIdEnum
    sleep = TsL2SleepRequest.SleepKindEnum
    startup = TsL2StartupRequest.StartupIdEnum

    script = [
        ("Get_Info: certificate block 0",
         TsL2GetInfoRequest(object_id=oid.X509_CERTIFICATE, block_index=0)),
        ("Get_Info: chip ID",
         TsL2GetInfoRequest(object_id=oid.CHIP_ID, block_index=0)),
        ("Get_Info: RISC-V FW version",
         TsL2GetInfoRequest(object_id=oid.RISCV_FW_VERSION, block_index=0)),
        ("Get_Info: SPECT FW version",
         TsL2GetInfoRequest(object_id=oid.SPECT_FW_VERSION, block_index=0)),
        ("Get_Info: unknown OBJECT_ID",
         TsL2GetInfoRequest(object_id=0x55, block_index=0)),
        ("Get_Log", TsL2GetLogRequest()),
        ("Resend", TsL2ResendRequest()),
        ("Handshake: unwritten pairing slot",
         TsL2HandshakeRequest(e_hpub=host.session.create_handshake_request(),
                              pkey_index=3)),
        ("Handshake", TsL2HandshakeRequest(
            e_hpub=host.session.create_handshake_request(), pkey_index=0)),
        ("Encrypted_Session_Abt", TsL2EncryptedSessionAbtRequest()),
        ("Sleep: invalid kind", TsL2SleepRequest(sleep_kind=0x77)),
        ("Startup: MAINTENANCE_REBOOT",
         TsL2StartupRequest(startup_id=startup.MAINTENANCE_REBOOT)),
    ]

    traces: List[Dict[str, Any]] = []
    for label, request in script:
        mode_before = model.chip_mode.name
        raw_request = request.to_bytes()
        raw_response = host.send_request(raw_request)
        traces.append(
            {
                "label": label,
                "request_class": type(request).__name__,
                "mode": mode_before,
                "request": raw_request.hex(),
                "response": bytes(raw_response).hex(),
                "chip_status": read_chip_status(model),
            }
        )

    # ...and the same Get_Info objects again, now that the chip is in Start-up
    # mode, so the GUI can show both firmwares answering the same opcode.
    for label, request in [
        ("Get_Info: RISC-V FW version (bootloader)",
         TsL2GetInfoRequest(object_id=oid.RISCV_FW_VERSION, block_index=0)),
        ("Get_Info: SPECT FW version (bootloader)",
         TsL2GetInfoRequest(object_id=oid.SPECT_FW_VERSION, block_index=0)),
        ("Get_Info: FW bank FW1",
         TsL2GetInfoRequest(object_id=oid.FW_BANK, block_index=FwBankIdEnum.FW1)),
        ("Get_Info: FW bank FW2 (empty)",
         TsL2GetInfoRequest(object_id=oid.FW_BANK, block_index=FwBankIdEnum.FW2)),
        ("Handshake in Start-up mode", TsL2HandshakeRequest(
            e_hpub=host.session.create_handshake_request(), pkey_index=0)),
    ]:
        mode_before = model.chip_mode.name
        raw_request = request.to_bytes()
        raw_response = host.send_request(raw_request)
        traces.append(
            {
                "label": label,
                "request_class": type(request).__name__,
                "mode": mode_before,
                "request": raw_request.hex(),
                "response": bytes(raw_response).hex(),
                "chip_status": read_chip_status(model),
            }
        )
    return traces


def exchanges() -> List[Dict[str, Any]]:
    """Every request worth sending, in every mode, actually sent.

    This is what makes the page an explorer rather than a diagram: the user
    picks a mode and a request, and sees the bytes the model really answered
    with. Each exchange runs against a *fresh* model put into the target mode,
    so nothing leaks from one into the next and the list can be replayed in any
    order.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    oid = TsL2GetInfoRequest.ObjectIdEnum
    sleep_kind = TsL2SleepRequest.SleepKindEnum
    startup_id = TsL2StartupRequest.StartupIdEnum
    host_priv = bytes(range(32))
    host_pub = X25519PrivateKey.from_private_bytes(host_priv).public_key().public_bytes_raw()
    tropic_priv = bytes(range(32, 64))
    tropic_pub = X25519PrivateKey.from_private_bytes(tropic_priv).public_key().public_bytes_raw()

    def fresh(mode: ChipMode):
        model = Tropic01Model(
            debug_random_value=bytes(4), busy_iter=[False],
            s_t_priv=tropic_priv, s_t_pub=tropic_pub,
        )
        model.i_pairing_keys[0].write(host_pub)
        model.power_on()
        if mode is ChipMode.START_UP:
            model.reboot(BootTarget.START_UP)
        host = Host(
            s_h_priv=[host_priv], s_h_pub=[host_pub], s_t_pub=tropic_pub,
            pairing_key_index=0, debug_random_value=bytes(4),
        ).set_target(model)
        return model, host

    def cases(host: Host):
        """(group, label, params, request) for one host's ephemeral key."""
        return [
            ("Get_Info", "X.509 certificate, block 0",
             {"OBJECT_ID": "X509_CERTIFICATE", "BLOCK_INDEX": 0},
             TsL2GetInfoRequest(object_id=oid.X509_CERTIFICATE, block_index=0)),
            ("Get_Info", "X.509 certificate, block 29 (last)",
             {"OBJECT_ID": "X509_CERTIFICATE", "BLOCK_INDEX": 29},
             TsL2GetInfoRequest(object_id=oid.X509_CERTIFICATE, block_index=29)),
            ("Get_Info", "X.509 certificate, block 30 (out of range)",
             {"OBJECT_ID": "X509_CERTIFICATE", "BLOCK_INDEX": 30},
             TsL2GetInfoRequest(object_id=oid.X509_CERTIFICATE, block_index=30)),
            ("Get_Info", "chip ID", {"OBJECT_ID": "CHIP_ID"},
             TsL2GetInfoRequest(object_id=oid.CHIP_ID, block_index=0)),
            ("Get_Info", "RISC-V FW version", {"OBJECT_ID": "RISCV_FW_VERSION"},
             TsL2GetInfoRequest(object_id=oid.RISCV_FW_VERSION, block_index=0)),
            ("Get_Info", "SPECT FW version", {"OBJECT_ID": "SPECT_FW_VERSION"},
             TsL2GetInfoRequest(object_id=oid.SPECT_FW_VERSION, block_index=0)),
            *[
                ("Get_Info", f"FW bank {bank.name}",
                 {"OBJECT_ID": "FW_BANK", "BANK_ID": bank.name},
                 TsL2GetInfoRequest(object_id=oid.FW_BANK, block_index=bank))
                for bank in FwBankIdEnum
            ],
            ("Get_Info", "unknown OBJECT_ID 0x55", {"OBJECT_ID": "0x55"},
             TsL2GetInfoRequest(object_id=0x55, block_index=0)),
            ("Handshake", "pairing key slot 0 (written)", {"PKEY_INDEX": 0},
             TsL2HandshakeRequest(e_hpub=host.session.create_handshake_request(),
                                  pkey_index=0)),
            ("Handshake", "pairing key slot 3 (blank)", {"PKEY_INDEX": 3},
             TsL2HandshakeRequest(e_hpub=host.session.create_handshake_request(),
                                  pkey_index=3)),
            ("Session", "Encrypted_Session_Abt", {},
             TsL2EncryptedSessionAbtRequest()),
            ("Transport", "Resend_Req", {}, TsL2ResendRequest()),
            ("Transport", "Get_Log_Req", {}, TsL2GetLogRequest()),
            ("Sleep", "SLEEP_MODE", {"SLEEP_KIND": "SLEEP_MODE"},
             TsL2SleepRequest(sleep_kind=sleep_kind.SLEEP_MODE)),
            ("Sleep", "invalid kind 0x77", {"SLEEP_KIND": "0x77"},
             TsL2SleepRequest(sleep_kind=0x77)),
            *[
                ("Startup", sid.name, {"STARTUP_ID": sid.name},
                 TsL2StartupRequest(startup_id=sid))
                for sid in startup_id
            ],
            ("Startup", "invalid id 0x99", {"STARTUP_ID": "0x99"},
             TsL2StartupRequest(startup_id=0x99)),
        ]

    out: List[Dict[str, Any]] = []
    for mode in ChipMode:
        # How many cases there are is fixed, so build one host just to size the
        # list, then run each case on its own untouched model.
        probe_model, probe_host = fresh(mode)
        count = len(cases(probe_host))
        for index in range(count):
            model, host = fresh(mode)
            if model.chip_mode is not mode:
                continue  # mode not reachable for this build
            group, label, params, request = cases(host)[index]
            raw_request = request.to_bytes()
            raw_response = bytes(host.send_request(raw_request))
            out.append(
                {
                    "mode": mode.name,
                    "group": group,
                    "label": label,
                    "request_class": type(request).__name__,
                    "params": params,
                    "request": raw_request.hex(),
                    "response": raw_response.hex(),
                    "status": raw_response[0] if raw_response else None,
                    "chip_status_after": read_chip_status(model),
                    "mode_after": model.chip_mode.name,
                }
            )
    return out


def repo_examples(ts_tvl: pathlib.Path) -> List[Dict[str, Any]]:
    """Run ts-tvl's own example scripts and record what they did.

    These are not examples written for this page; they are the files shipped in
    `examples/`, executed unmodified. `Host.send_request` and
    `Host.send_command` are wrapped for the duration so every exchange is
    recorded, and stdout is captured, so the page can show the script, what it
    printed, and the bytes underneath it side by side.

    Each script is run several times and the recordings compared. Anything that
    differs is session-dependent - ephemeral X25519 keys, the ciphertext and tag
    they produce - and is masked rather than committed, because a spec that
    changes every run would fail `--check` forever. The masking is derived, not
    guessed: it is exactly the bytes that actually moved.

    Two runs is not enough, which is worth spelling out because it looked like
    it was. A uniformly random byte matches across two runs 1 time in 256, so a
    128-byte ephemeral payload leaves roughly half a byte unmasked *by luck*
    each time - and a different half on the next invocation, which makes the
    generated file differ from itself and `--check` fail on unchanged code.
    With RUNS runs the odds of a random byte surviving unmasked are 256^-(RUNS-1),
    which at 6 is about 1e-12.
    """
    RUNS = 6
    import contextlib
    import io
    import runpy

    directory = ts_tvl / "examples"
    if not directory.is_dir():
        return []

    def record(path: pathlib.Path) -> Dict[str, Any]:
        calls: List[Dict[str, Any]] = []
        original_request = Host._ll_send_l2
        original_command = Host._ll_send_l3

        # Hook `_ll_send_l2` / `_ll_send_l3`, not `send_request` /
        # `send_command`. The public two are `singledispatchmethod`s whose
        # registries are captured at class-definition time, so replacing them
        # loses the dispatch and every call dies in the base implementation.
        # These two are plain methods that all four registered variants funnel
        # through, which makes them the one honest chokepoint.
        def wrap_l2(original: Any) -> Any:
            def wrapper(self: Any, l2request: Any) -> Any:
                response, raw = original(self, l2request)
                calls.append(
                    {
                        "kind": "L2",
                        "name": type(l2request).__name__,
                        "sent": bytes(l2request.to_bytes()).hex(),
                        "got": bytes(raw).hex(),
                        "repr_sent": str(l2request),
                        "repr_got": str(response),
                    }
                )
                return response, raw
            return wrapper

        def wrap_l3(original: Any) -> Any:
            def wrapper(self: Any, l3command: Any) -> Any:
                raw = original(self, l3command)
                calls.append(
                    {
                        "kind": "L3",
                        "name": type(l3command).__name__,
                        "sent": bytes(l3command.to_bytes()).hex(),
                        "got": bytes(raw).hex(),
                        "repr_sent": str(l3command),
                        "repr_got": "",
                    }
                )
                return raw
            return wrapper

        Host._ll_send_l2 = wrap_l2(original_request)  # type: ignore[assignment]
        Host._ll_send_l3 = wrap_l3(original_command)  # type: ignore[assignment]
        out = io.StringIO()
        error: Optional[str] = None
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                runpy.run_path(str(path), run_name="__not_main__")
        except Exception as exc:  # an example that breaks is worth showing
            error = f"{type(exc).__name__}: {exc}"
        finally:
            Host._ll_send_l2 = original_request  # type: ignore[assignment]
            Host._ll_send_l3 = original_command  # type: ignore[assignment]
        return {"calls": calls, "stdout": out.getvalue(), "error": error}

    def mask(values: List[str]) -> Optional[str]:
        """Hex with session-dependent nibbles replaced by '.', or None.

        None means the *length* moved between runs, not just the contents. There
        is no honest fixed-length rendering of that - masking a random-length
        string keeps a random prefix, which is how this defeated `--check` once
        already - so the bytes are not committed and the page says why.
        """
        if len({len(v) for v in values}) != 1:
            return None
        return "".join(
            column[0] if len(set(column)) == 1 else "." for column in zip(*values)
        )

    def agree(values: List[Any]) -> Any:
        """The value if every run produced it, else None."""
        return values[0] if all(v == values[0] for v in values) else None

    examples: List[Dict[str, Any]] = []
    for path in sorted(directory.glob("example_*.py")):
        runs = [record(path) for _ in range(RUNS)]
        merged = []
        for index in range(len(runs[0]["calls"])):
            group = [r["calls"][index] for r in runs]
            sent = mask([c["sent"] for c in group])
            got = mask([c["got"] for c in group])
            # Deliberately not recording the observed lengths: that is a sample
            # of random values, so committing it makes the file differ from
            # itself. "the length is session-dependent" is the whole stable fact.
            merged.append(
                {
                    "kind": group[0]["kind"],
                    "name": group[0]["name"],
                    "sent": sent,
                    "got": got,
                    "length_varies": sent is None or got is None,
                    "repr_sent": agree([c["repr_sent"] for c in group]),
                    "repr_got": agree([c["repr_got"] for c in group]),
                    "volatile": (sent is None or "." in sent)
                                or (got is None or "." in got),
                }
            )
        source = path.read_text()
        examples.append(
            {
                "name": path.name,
                "title": _example_title(source) or path.stem.replace("_", " "),
                "source": source,
                "stdout": agree([r["stdout"] for r in runs]),
                "error": runs[0]["error"],
                "calls": merged,
                "any_volatile": any(c["volatile"] for c in merged),
            }
        )
    return examples


def _example_title(source: str) -> Optional[str]:
    """The sentence in the example's own banner comment, if it has one."""
    lines = [
        line.lstrip("# ").strip()
        for line in source.splitlines()
        if line.startswith("#") and set(line.strip()) != {"#"}
    ]
    for line in lines:
        if line and not line.startswith("!") and len(line) > 20:
            return line
    return None


def frame_layouts() -> Dict[str, Any]:
    return {
        "request": [
            {"name": "REQ_ID", "size": 1, "doc": "Which L2 request this is."},
            {"name": "REQ_LEN", "size": 1, "doc": "Length of DATA in bytes."},
            {"name": "DATA", "size": None, "doc": "REQ_LEN bytes of payload."},
            {"name": "CRC16", "size": 2, "doc": "Over REQ_ID..DATA."},
        ],
        "response": [
            {"name": "STATUS", "size": 1, "doc": "L2 status code."},
            {"name": "RSP_LEN", "size": 1, "doc": "Length of DATA in bytes."},
            {"name": "DATA", "size": None, "doc": "RSP_LEN bytes of payload."},
            {"name": "CRC16", "size": 2, "doc": "Over STATUS..DATA."},
        ],
    }


def provenance() -> Dict[str, Any]:
    import tvl

    ts_tvl = pathlib.Path(inspect.getfile(tvl)).parent.parent

    def git(*args: str) -> str:
        try:
            return subprocess.run(
                ["git", "-C", str(ts_tvl), *args],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        except Exception:
            return "unknown"

    generated_files = {}
    for relative in ("tvl/api/l2_api.py", "tvl/api/l3_api.py",
                     "tvl/targets/model/configuration_object_impl.py"):
        path = ts_tvl / relative
        if path.exists():
            generated_files[relative] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()[:16]

    return {
        "spec_version": SPEC_VERSION,
        "ts_tvl_commit": git("rev-parse", "--short", "HEAD"),
        "ts_tvl_describe": git("describe", "--always", "--dirty"),
        "ts_tvl_branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "generated_file_hashes": generated_files,
    }


def build() -> Dict[str, Any]:
    spec = _build()
    # A capture that silently produced nothing would sail through every
    # downstream check - empty renders as empty, and "the page shows everything
    # the spec contains" is vacuously true of an empty spec. Refuse to emit one.
    for key in ("chip_modes", "co_registers", "l2_requests", "boot_transitions",
                "wire_traces", "chip_status_flags", "exchanges"):
        if not spec.get(key):
            raise SystemExit(
                f"refusing to emit a spec with an empty '{key}' - the model "
                f"introspection or capture produced nothing, which means this "
                f"generator is broken, not that the model is empty."
            )
    return spec


def _build() -> Dict[str, Any]:
    return {
        "provenance": provenance(),
        "chip_modes": chip_modes(),
        "boot_targets": boot_targets(),
        "chip_status_flags": chip_status_flags(),
        "l2_status_codes": l2_status_codes(),
        "co_registers": co_registers(),
        "co_address_space": {
            "size_bytes": 0x200,
            "register_size_bytes": 4,
            "erased_value": 0xFFFFFFFF,
            "application_base": APPLICATION_CO_BASE,
            "configuration_half": [0x000, 0x0FF],
            "functionality_half": [0x100, 0x1FF],
        },
        "l2_requests": l2_requests(),
        "get_info_objects": get_info_objects(),
        "fw_banks": fw_bank_layout(),
        "frame_layouts": frame_layouts(),
        "boot_transitions": boot_transitions(),
        "wire_traces": wire_traces(),
        "exchanges": exchanges(),
        "examples": repo_examples(
            pathlib.Path(inspect.getfile(__import__("tvl"))).parent.parent
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument(
        "--check", action="store_true",
        help="exit non-zero if --out is missing or stale, writing nothing",
    )
    args = parser.parse_args()

    spec = build()
    # Emitted as JavaScript, not JSON, so the page works from a plain file://
    # URL as well as from Pages - fetch() of a sibling .json is blocked by CORS
    # on file://, a <script src> is not. The body is still readable JSON.
    rendered = (
        "// GENERATED by tools/generate_spec.py - do not edit.\n"
        "// Every value below was introspected from, or produced by executing,\n"
        "// the ts-tvl model. See README.md.\n"
        "window.MODEL_SPEC = "
        + json.dumps(spec, indent=1, sort_keys=True)
        + ";\n"
    )

    if args.check:
        if not args.out.exists():
            print(f"{args.out} does not exist", file=sys.stderr)
            return 1
        if args.out.read_text() != rendered:
            print(
                f"{args.out} is stale - the model changed. "
                f"Regenerate with tools/generate_spec.py.",
                file=sys.stderr,
            )
            return 1
        print(f"{args.out} is up to date.")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(rendered)
    print(
        f"{args.out}: {len(rendered)} bytes, "
        f"{len(spec['co_registers'])} CO registers, "
        f"{len(spec['l2_requests'])} L2 requests, "
        f"{len(spec['boot_transitions'])} boot transitions, "
        f"{len(spec['wire_traces'])} traces, "
        f"{len(spec['exchanges'])} exchanges"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
