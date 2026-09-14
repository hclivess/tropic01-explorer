#!/usr/bin/env python3
"""Emit the explorer's entire dataset by introspecting and executing ts-tvl.

Nothing in `docs/` is written by hand. Every register, field, address, gating
rule, status byte, frame layout and wire byte in the GUI comes from here, and
this script gets all of it in one of exactly two ways:

1. **Introspection** of the live objects (`ConfigurationObjectImpl`, `L2Enum`,
   `L2_REQUEST_MODES`, `_HEADER`, ...) plus `ast` for the docstrings
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
import contextlib
import hashlib
import inspect
import itertools
import json
import pathlib
import re
import subprocess
import sys
import textwrap
import types
from typing import Any, Callable, Dict, List, Optional, Tuple

from tvl.api.l2_api import (
    L2Enum,
    TsL2EncryptedCmdRequest,
    TsL2EncryptedSessionAbtRequest,
    TsL2GetInfoRequest,
    TsL2GetLogRequest,
    TsL2HandshakeRequest,
    TsL2ResendRequest,
    TsL2SleepRequest,
    TsL2StartupRequest,
)
from tvl.api import l3_api as l3_mod
from tvl.api.l3_api import L3Enum
from tvl.constants import (
    CERTIFICATE_SIZE, CHIP_ID_SIZE, L1ChipStatusFlag, L2IdFieldEnum, L2StatusEnum,
    L3ResultFieldEnum, S_HI_PUB_NB_SLOTS,
)
from tvl.messages.l3_messages import L3Command, L3Result
from tvl.targets.model import tropic01_l3_api_impl as l3_impl
from tvl.targets.model.internal import mac_and_destroy as mad_mod
from tvl.targets.model.internal import mcounter as mcounter_mod
from tvl.targets.model.internal import pairing_keys as pairing_mod
from tvl.targets.model.internal import user_data_partition as udata_mod
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
            # A reason may sit on the row itself, after the value.
            if (trailing := re.search(r"#\s?(.*)$", line)) is not None:
                reasons[current].append(trailing.group(1).strip())
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
                "provider": provider.__name__,
                # The provider's own docstring says what it serves.
                "doc": " ".join((provider.__doc__ or "").split()),
            }
            for object_id, provider in sorted(providers.items())
        ]
        for mode, providers in l2_impl.L2APIImplementation.GET_INFO_OBJECTS.items()
    }


def fw_bank_layout() -> Dict[str, Any]:
    docs = attribute_docs(fw_bank_mod)
    # The header layout is a struct format string; derive the field sizes from
    # it rather than restating them, so a change to the struct shows up here.
    fmt = fw_bank_mod._HEADER.format
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
        "default_populated": sorted(int(b) for b in FwBanks().banks),
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
        raw_request: Optional[bytes] = None
        raw_response: Optional[bytes] = None
        if action == "POWER_ON":
            model.power_on()
        else:
            host = Host().set_target(model)
            # Raw bytes in, raw bytes out - the same frames the Try-it tab shows.
            raw_request = TsL2StartupRequest(
                startup_id=getattr(startup, action)
            ).to_bytes()
            raw_response = bytes(host.send_request(raw_request))
            status = raw_response[0]
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
                "request": raw_request.hex() if raw_request else None,
                "response": raw_response.hex() if raw_response else None,
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


def decode_fw_version(raw: bytes) -> Dict[str, Any]:
    """Invert `encode_fw_version`, which packs, little-endian,

        (major << 24) | (minor << 16) | (patch << 8) | (commits << 1) | dirty

    with bit 31 doubling as FW_VERSION_MAINTENANCE_FLAG - which is why the major
    byte is masked to 7 bits when the flag is set.

    This is the one inverse written by hand in this file, so it is checked
    against the real encoder at generation time (`_check_version_roundtrip`)
    rather than trusted.
    """
    from tvl.constants import FW_VERSION_MAINTENANCE_FLAG

    word = int.from_bytes(raw, "little")
    flag = bool(word & FW_VERSION_MAINTENANCE_FLAG)
    major, minor, patch = (word >> 24) & 0x7F, (word >> 16) & 0xFF, (word >> 8) & 0xFF
    commits, dirty = (word >> 1) & 0x7F, bool(word & 1)
    text = f"{major}.{minor}.{patch}"
    if commits:
        text += f"-{commits}"
    if dirty:
        text += "-dirty"
    return {
        "kind": "fw_version",
        "version": text,
        "major": major, "minor": minor, "patch": patch,
        "commits": commits, "dirty": dirty,
        "maintenance_flag": flag,
        "word": f"{word:#010x}",
    }


def _check_version_roundtrip() -> None:
    """decode(encode(v)) == v, and the one place that is provably impossible.

    FW_VERSION_MAINTENANCE_FLAG is `1 << 31`, which is bit 7 of the *major
    version byte*. So the flag and a major version of 128 or more occupy the
    same bit: `with_maintenance_flag()` is a no-op on such a version, and no
    reader can tell the two apart. libtropic has the same ambiguity - it reads
    the major byte as `v[3] & 0x7f` unconditionally.

    Round-tripping is therefore asserted for major <= 127, and the ambiguity is
    asserted explicitly for major >= 128, so that a change to either the
    encoding or the flag makes this fail rather than pass quietly.
    """
    from tvl import constants as C

    for text in [
        C.RISCV_FW_VERSION_STR,
        C.SPECT_FW_VERSION_STR,
        decode_fw_version(C.BOOTLOADER_RISCV_FW_VERSION_DEFAULT)["version"],
        "0.0.0", "1.2.3", "7.8.9-5", "2.0.1-3-dirty", "127.255.255",
    ]:
        encoded = C.encode_fw_version(text)
        for flagged in (encoded, C.with_maintenance_flag(encoded)):
            got = decode_fw_version(flagged)["version"]
            if got != text:
                raise SystemExit(
                    f"decode_fw_version disagrees with encode_fw_version: "
                    f"{text!r} -> {flagged.hex()} -> {got!r}. The hand-written "
                    f"inverse in this file no longer matches the model."
                )

    for text in ("128.0.0", "255.255.255"):
        encoded = C.encode_fw_version(text)
        if C.with_maintenance_flag(encoded) != encoded:
            raise SystemExit(
                f"the maintenance flag no longer collides with major >= 128 "
                f"({text}) - the encoding or the flag changed, and the note in "
                f"SPEC_GAPS about this ambiguity needs revisiting."
            )


def decode_payload(object_id: Optional[int], payload: bytes) -> Optional[Dict[str, Any]]:
    """What a Get_Info payload actually means, worked out in Python.

    The page renders this; it does not compute it. Layouts come from the model
    (`_HEADER` via `fw_bank_layout()`), not from a copy kept here.
    """
    from tvl.api.l2_api import TsL2GetInfoRequest

    oid = TsL2GetInfoRequest.ObjectIdEnum
    if not payload or object_id is None:
        return None

    if object_id in (oid.RISCV_FW_VERSION, oid.SPECT_FW_VERSION) and len(payload) == 4:
        return decode_fw_version(payload)

    if object_id == oid.FW_BANK:
        layout = fw_bank_layout()
        if len(payload) != layout["header_size"]:
            return {"kind": "fw_bank", "empty": True,
                    "note": f"{len(payload)} bytes - an empty bank reports none"}
        fields = []
        for field in layout["fields"]:
            chunk = payload[field["offset"]: field["offset"] + field["size"]]
            entry = {
                "name": field["name"], "offset": field["offset"],
                "hex": chunk.hex(), "doc": field["doc"],
            }
            if field["name"] == "version" and len(chunk) == 4:
                entry["decoded"] = decode_fw_version(chunk)["version"]
            elif field["size"] <= 4:
                # The header struct is little-endian ("<HBB4sII32sI"), so say
                # so on anything wider than a byte rather than leaving a bare
                # number next to bytes in the opposite order.
                entry["decoded"] = str(int.from_bytes(chunk, "little")) + (
                    "  (little-endian)" if field["size"] > 1 else ""
                )
            fields.append(entry)
        return {"kind": "fw_bank", "empty": False, "fields": fields}

    if object_id == oid.CHIP_ID:
        runs = [
            {"offset": m.start(), "text": m.group().decode()}
            for m in re.finditer(rb"[ -~]{4,}", payload)
        ]
        return {"kind": "chip_id", "size": len(payload), "ascii": runs}

    if object_id == oid.X509_CERTIFICATE:
        return {"kind": "certificate", "size": len(payload),
                "note": "one 128-byte block of the certificate store"}
    return None


def request_cases(host: Host):
    """(group, label, params, request) for one host's ephemeral key - the list
    the Try-it tab sends and the Walkthrough tab traces."""
    oid = TsL2GetInfoRequest.ObjectIdEnum
    sleep_kind = TsL2SleepRequest.SleepKindEnum
    startup_id = TsL2StartupRequest.StartupIdEnum
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
        ("Session", "Encrypted_Cmd_Req with no session",
         {"L3_CHUNK": "8 bytes of nonsense"},
         TsL2EncryptedCmdRequest(l3_chunk=bytes(range(8)))),
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
        # The two Configuration Object gates. An all-ones config never reaches
        # them, so each carries the R-config that clears its bit.
        ("Startup", "MAINTENANCE_REBOOT with CFG_START_UP.MAINTENANCE_ENA = 0",
         {"STARTUP_ID": "MAINTENANCE_REBOOT", "MAINTENANCE_ENA": 0},
         TsL2StartupRequest(startup_id=startup_id.MAINTENANCE_REBOOT),
         {"cfg_start_up": 0xFFFF_FFF7}),
        ("Transport", "Get_Log_Req with CFG_DEBUG.FW_LOG_EN = 0", {"FW_LOG_EN": 0},
         TsL2GetLogRequest(), {"cfg_debug": 0xFFFF_FFFE}),
    ]


def case_config(case: tuple) -> Optional[Dict[str, int]]:
    """The R-config a case wants, or None for the all-ones default."""
    return case[4] if len(case) > 4 else None


def exchanges() -> List[Dict[str, Any]]:
    """Every request worth sending, in every mode, actually sent.

    This is what makes the page an explorer rather than a diagram: the user
    picks a mode and a request, and sees the bytes the model really answered
    with. Each exchange runs against a *fresh* model put into the target mode,
    so nothing leaks from one into the next and the list can be replayed in any
    order.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    host_priv = bytes(range(32))
    host_pub = X25519PrivateKey.from_private_bytes(host_priv).public_key().public_bytes_raw()
    tropic_priv = bytes(range(32, 64))
    tropic_pub = X25519PrivateKey.from_private_bytes(tropic_priv).public_key().public_bytes_raw()

    def fresh(mode: ChipMode, r_config: Optional[Dict[str, int]] = None):
        model = Tropic01Model(
            debug_random_value=bytes(4), busy_iter=[False],
            s_t_priv=tropic_priv, s_t_pub=tropic_pub,
            **({"r_config": ConfigurationObjectImpl.from_dict(r_config)} if r_config else {}),
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

    out: List[Dict[str, Any]] = []
    for mode in ChipMode:
        # The list is fixed, so build one host just to read it, then run each
        # case on its own untouched model - with that case's R-config, if any.
        probe = request_cases(fresh(mode)[1])
        for index in range(len(probe)):
            model, host = fresh(mode, case_config(probe[index]))
            if model.chip_mode is not mode:
                continue  # mode not reachable for this build
            group, label, params, request = request_cases(host)[index][:4]
            raw_request = request.to_bytes()
            with spi_capture(model) as transactions:
                raw_response = bytes(host.send_request(raw_request))
            payload = raw_response[2:-2] if len(raw_response) >= 4 else b""
            object_id = getattr(request, "object_id", None)
            out.append(
                {
                    "decoded": decode_payload(
                        int(object_id.value) if object_id is not None else None,
                        payload,
                    ),
                    "mode": mode.name,
                    "group": group,
                    "label": label,
                    "request_class": type(request).__name__,
                    "params": params,
                    # The REQ_ID is literally the first byte, so the link from
                    # an L2_REQUEST_MODES row to an exchange is exact rather
                    # than a name match.
                    "request_id": raw_request[0],
                    "object_id": int(object_id.value) if object_id is not None else None,
                    "request": raw_request.hex(),
                    "response": raw_response.hex(),
                    "status": raw_response[0] if raw_response else None,
                    "chip_status_after": read_chip_status(model),
                    "mode_after": model.chip_mode.name,
                    # L1: every chip-select low..high the host drove for this
                    # exchange, MOSI and MISO, first MISO byte = CHIP_STATUS.
                    "transactions": transactions,
                }
            )
    return out



def call_traces() -> Dict[str, Any]:
    """How the model's code actually traverses, for a handful of requests.

    Not a description of the call graph: each scenario is run under
    `sys.settrace` and every call into, and return out of, the model's own
    modules is recorded - file, function, line, depth, and what came back. The
    page steps through that record. Only the model's files are kept (plus the
    host's entry point), so the trace is the spine and not the framing library.
    """
    import inspect
    import sys

    from tvl.constants import L2IdFieldEnum

    root = pathlib.Path(inspect.getfile(Host)).resolve().parents[2]  # .../tvl/host/host.py
    keep = (
        "tvl/targets/model/base_model.py",
        "tvl/targets/model/tropic01_l2_api_impl.py",
        "tvl/targets/model/internal/spi_fsm.py",
        "tvl/targets/model/internal/chip_mode.py",
        "tvl/targets/model/internal/fw_bank.py",
        "tvl/targets/model/tropic01_l3_api_impl.py",
        "tvl/targets/model/internal/command_buffer.py",
        "tvl/targets/model/internal/pairing_keys.py",
        "tvl/targets/model/internal/ecc_keys.py",
        "tvl/targets/model/internal/mcounter.py",
        "tvl/targets/model/internal/user_data_partition.py",
        "tvl/targets/model/internal/mac_and_destroy.py",
        "tvl/crypto/encrypted_session.py",
        "tvl/host/host.py",
    )
    # Property getters and comprehensions are noise; the CO internals (27
    # registers ANDed on every `self.config`) would swamp the boot scenario.
    skip_names = {"set_logger", "target_driver", "<genexpr>", "<listcomp>", "<dictcomp>", "<setcomp>"}
    MAX_STEPS, MAX_DEPTH = 900, 14

    def scrub(text: str) -> str:
        return re.sub(r"(<[^<>]*? at )0x[0-9a-f]+(>)", r"\g<1>0x...\g<2>", text)

    def show(value: Any) -> str:
        if isinstance(value, (bytes, bytearray)):
            h = bytes(value).hex(" ")
            return h if len(value) <= 24 else h[:71] + " …"
        if hasattr(value, "name") and hasattr(value, "value"):
            return f"{type(value).__name__}.{value.name}"
        text = scrub(str(value))
        return text if len(text) <= 80 else text[:77] + "…"

    sources: Dict[str, Dict[str, Any]] = {}
    names: Dict[Any, str] = {}

    def display_name(code: Any) -> str:
        """The qualname - except a singledispatch overload registered as `def _`,
        which is shown under the name it overloads, read off its decorator."""
        if code in names:
            return names[code]
        name = getattr(code, "co_qualname", code.co_name)
        if code.co_name == "_":
            try:
                first = inspect.getsourcelines(code)[0][0]
                m = re.match(r"\s*@(\w+)\.register", first)
                if m:
                    name = name[: -len("_")] + m.group(1) + " (overload)"
            except (OSError, TypeError):
                pass
        names[code] = name
        return name

    def record(scenario: Dict[str, Any], run: Any) -> None:
        steps: List[Dict[str, Any]] = []
        depth = [0]

        def local(frame: Any, event: str, arg: Any) -> Any:
            if event == "return":
                code = frame.f_code
                if depth[0] <= MAX_DEPTH and len(steps) < MAX_STEPS:
                    steps.append({
                        "event": "return", "depth": depth[0],
                        "file": str(pathlib.Path(code.co_filename).resolve().relative_to(root)),
                        "function": display_name(code),
                        "line": frame.f_lineno, "value": show(arg),
                    })
                depth[0] -= 1
            return local

        def tracer(frame: Any, event: str, arg: Any) -> Any:
            if event != "call":
                return None
            code = frame.f_code
            try:
                rel = str(pathlib.Path(code.co_filename).resolve().relative_to(root))
            except ValueError:
                return None
            name = display_name(code)
            if rel not in keep or code.co_name in skip_names:
                return None
            depth[0] += 1
            if depth[0] <= MAX_DEPTH and len(steps) < MAX_STEPS:
                steps.append({"event": "call", "depth": depth[0], "file": rel,
                              "function": name, "line": frame.f_lineno, "value": None})
                key = f"{rel}::{name}"
                if key not in sources:
                    try:
                        lines, first = inspect.getsourcelines(code)
                        sources[key] = {"first_line": first, "text": "".join(lines[:60])}
                    except (OSError, TypeError):
                        pass
            return local

        sys.settrace(tracer)
        try:
            run()
        finally:
            sys.settrace(None)
        scenario["steps"] = steps
        scenario["truncated"] = len(steps) >= MAX_STEPS

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    host_priv = bytes(range(32))
    host_pub = X25519PrivateKey.from_private_bytes(host_priv).public_key().public_bytes_raw()
    tropic_priv = bytes(range(32, 64))
    tropic_pub = X25519PrivateKey.from_private_bytes(tropic_priv).public_key().public_bytes_raw()

    def fresh(mode: ChipMode, *, r_config: Optional[Dict[str, int]] = None):
        model = Tropic01Model(
            debug_random_value=bytes(4), busy_iter=[False],
            s_t_priv=tropic_priv, s_t_pub=tropic_pub,
            **({"r_config": ConfigurationObjectImpl.from_dict(r_config)} if r_config else {}),
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

    scenarios: List[Dict[str, Any]] = []

    def scenario(title: str, mode: ChipMode, request: Any, *, then_read: bool = False,
                 r_config: Optional[Dict[str, int]] = None, note: str = "",
                 host: Optional[Host] = None, model: Optional[Tropic01Model] = None,
                 group: str = "", label: str = "", layer: str = "L2") -> None:
        if model is None or host is None:
            model, host = fresh(mode, r_config=r_config)
        # group/label match the Try-it exchange this scenario belongs to.
        entry = {"title": title, "mode": mode.name, "request_class": type(request).__name__,
                 "request": request.to_bytes().hex(), "note": note,
                 "group": group, "label": label, "layer": layer}

        def run() -> None:
            if layer == "L3":
                entry["response"] = host.send_command(request).to_bytes().hex()
                return
            entry["response"] = bytes(host.send_request(request.to_bytes())).hex()
            if then_read:
                # The restart lands on the next transaction, as it does on silicon.
                model.spi_drive_csn_low()
                model.spi_send(bytes([L2IdFieldEnum.GET_RESP]))
                model.spi_drive_csn_high()
            entry["mode_after"] = model.chip_mode.name

        record(entry, run)
        scenarios.append(entry)

    notes = {
        ("APPLICATION", "Get_Info", "chip ID"):
            "The plain path: SPI FSM, frame check, the gate, the handler, one provider.",
        ("APPLICATION", "Startup", "MAINTENANCE_REBOOT"):
            "The handler answers and schedules; the boot itself runs on the next transaction.",
        ("APPLICATION", "Startup", "MAINTENANCE_REBOOT with CFG_START_UP.MAINTENANCE_ENA = 0"):
            "Refused from the handler, as the firmware does; nothing is scheduled.",
        ("APPLICATION", "Transport", "Get_Log_Req with CFG_DEBUG.FW_LOG_EN = 0"):
            "A Configuration Object gate: RESP_DISABLED with no payload.",
        ("START_UP", "Handshake", "pairing key slot 0 (written)"):
            "Refused before any handler: the gate answers UNKNOWN_REQ.",
        ("START_UP", "Get_Info", "FW bank FW1"):
            "The Start-up table selects a provider the Application table does not have.",
    }
    # The Try-it list, every request in every mode, each on its own fresh model.
    # A Startup_Req is followed by the read that lands the restart, so the boot
    # shows up in the trace and not only in mode_after.
    for mode in ChipMode:
        probe = request_cases(fresh(mode)[1])
        for index in range(len(probe)):
            model, host = fresh(mode, r_config=case_config(probe[index]))
            group, label, _, request = request_cases(host)[index][:4]
            scenario(f"{group} · {label}", mode, request, model=model, host=host,
                     then_read=group == "Startup",
                     note=notes.get((mode.name, group, label), ""),
                     group=group, label=label)
    # L3: the same sequence Try it shows, one chip, one session, in order.
    model, host = paired_chip(); open_session(host)
    for group, label, _params, command, note, r_config in l3_cases():
        if r_config is not None:
            model_r, host_r = paired_chip(r_config); open_session(host_r)
            scenario(f"{group} · {label}", ChipMode.APPLICATION, command, model=model_r,
                     host=host_r, note=note, group=group, label=label, layer="L3")
            continue
        scenario(f"{group} · {label}", ChipMode.APPLICATION, command, model=model, host=host,
                 note=note, group=group, label=label, layer="L3")

    for sc in scenarios:
        if len(sc["steps"]) < 3:
            raise SystemExit(f"walkthrough {sc['title']!r} recorded {len(sc['steps'])} steps; "
                             "the tracer or the file whitelist no longer matches the model.")
    return {"scenarios": scenarios, "sources": sources}


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
    import hashlib
    import io
    import itertools
    import os
    import random
    import runpy

    from cryptography.hazmat.primitives.asymmetric import x25519

    @contextlib.contextmanager
    def pinned_entropy():
        """Make the examples reproducible instead of masking what moved.

        The secure-channel examples build ephemeral X25519 keys, so their bytes
        differ every run. Masking the difference is honest but useless - the page
        ends up showing dots where the interesting part is. Pinning the entropy
        instead gives real bytes, real output, and a capture that reproduces.

        This replaces the *source of randomness* for the duration of the
        capture. It does not touch the examples, the protocol, or the model.
        """
        counter = itertools.count()

        def stream(n: int) -> bytes:
            out = b""
            while len(out) < n:
                out += hashlib.sha256(
                    b"tropic01-explorer/" + str(next(counter)).encode()
                ).digest()
            return out[:n]

        real_urandom, real_generate = os.urandom, x25519.X25519PrivateKey.generate
        real_state = random.getstate()
        os.urandom = stream  # type: ignore[assignment]
        x25519.X25519PrivateKey.generate = staticmethod(  # type: ignore[assignment]
            lambda: x25519.X25519PrivateKey.from_private_bytes(stream(32))
        )
        # example_04 does `os.urandom(randint(1, 32))`, so the *length* of a
        # payload comes from Python's own RNG, not the OS one. Seeding both is
        # what turns "output varies between runs" into a real capture.
        random.seed(0)
        try:
            yield
        finally:
            os.urandom = real_urandom  # type: ignore[assignment]
            x25519.X25519PrivateKey.generate = real_generate  # type: ignore[assignment]
            random.setstate(real_state)

    directory = ts_tvl / "examples"
    if not directory.is_dir():
        return []

    @contextlib.contextmanager
    def captured_logs():
        """Collect what the examples log, instead of throwing it away.

        Every example calls `setup_logging()`, which runs `dictConfig` and so
        *replaces* the root handlers - a handler attached beforehand is
        discarded. So wrap `setup_logging` itself: let the real one run, then
        attach a capturing handler on top.

        The formatter is ts-tvl's own `TVLFormatter` with its own format string,
        colours off, so the text matches what a person running the script sees
        rather than a format invented here.
        """
        import logging

        from tvl import logging_utils

        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        # ts-tvl's own formatter and its own format string, colours off, so the
        # text matches what a person running the script sees.
        handler.setFormatter(
            logging_utils.TVLFormatter(
                use_colors=False,
                format="[%(name)s] [%(levelname)s] %(message)s",
            )
        )
        real_setup = logging_utils.setup_logging

        def setup_and_capture(*args: Any, **kwargs: Any) -> Any:
            result = real_setup(*args, **kwargs)
            # `dictConfig` defaults to disable_existing_loggers=True, and
            # `logging.getLogger("host")` returns the *same* object on every
            # run. So the first run logs and every run after it is silent - the
            # second `setup_logging()` disables the loggers the first created.
            # Each capture has to start like a fresh process, or the runs
            # disagree and the whole log is dropped as non-reproducible.
            for existing in logging.root.manager.loggerDict.values():
                if isinstance(existing, logging.Logger):
                    existing.disabled = False
            root = logging.getLogger()
            root.addHandler(handler)
            root.setLevel(logging.DEBUG)
            return result

        logging_utils.setup_logging = setup_and_capture  # type: ignore[assignment]
        try:
            yield buffer
        finally:
            logging_utils.setup_logging = real_setup  # type: ignore[assignment]
            logging.getLogger().removeHandler(handler)

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
        logs = ""
        try:
            with pinned_entropy(), captured_logs() as log_buffer, \
                 contextlib.redirect_stdout(out), \
                 contextlib.redirect_stderr(io.StringIO()):
                runpy.run_path(str(path), run_name="__not_main__")
                logs = log_buffer.getvalue()
        except Exception as exc:  # an example that breaks is worth showing
            error = f"{type(exc).__name__}: {exc}"
        finally:
            Host._ll_send_l2 = original_request  # type: ignore[assignment]
            Host._ll_send_l3 = original_command  # type: ignore[assignment]
        return {
            "calls": calls,
            "stdout": out.getvalue(),
            "logs": scrub(logs),
            "error": error,
        }

    def scrub(text: str) -> str:
        """Remove CPython object addresses from captured log text.

        The logs contain reprs like `<function ll_send_l2_request at
        0x76750c583100>`. The address is where the object happened to land in
        memory this process - it is not protocol content, and it is the only
        thing left that differs between runs once the entropy is pinned.
        Targeted narrowly at the `... at 0x...>` repr form so that genuine hex
        in the logs (`RSP_LEN: 0x80`, `<195: 0xc3>`) is untouched.
        """
        return re.sub(r"(<[^<>]*? at )0x[0-9a-f]+(>)", r"\g<1>0x...\g<2>", text)

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
                "logs": agree([r["logs"] for r in runs]),
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


def constants() -> Dict[str, Any]:
    """Everything `tvl.constants` exports, introspected.

    Nothing here is a list of names maintained by hand: the module is walked,
    each public name classified by what it actually is, and the docstrings
    recovered from source because Python discards the string literals that
    document module-level assignments. Add a constant to ts-tvl and it appears.
    """
    import enum as enum_mod

    from tvl import constants as C

    docs = module_level_docs(C)
    enum_docs = attribute_docs(C)

    enums: List[Dict[str, Any]] = []
    values: List[Dict[str, Any]] = []

    for name in sorted(dir(C)):
        if name.startswith("_"):
            continue
        value = getattr(C, name)
        # Skip things merely imported into the namespace (re, IntFlag, the
        # HexReprIntEnum base) rather than defined by this module.
        module = getattr(value, "__module__", None)
        if isinstance(value, types.ModuleType):
            continue
        if isinstance(value, type) and module != C.__name__:
            continue
        if callable(value) and not isinstance(value, type) and module != C.__name__:
            continue

        if isinstance(value, type) and issubclass(value, enum_mod.Enum):
            enums.append(
                {
                    "name": name,
                    "flag": issubclass(value, enum_mod.IntFlag),
                    "doc": " ".join((value.__doc__ or "").split())
                    if (value.__doc__ or "").strip() != "An enumeration."
                    else "",
                    "members": [
                        {
                            "name": member.name,
                            "value": int(member.value),
                            "bits": int(member.value).bit_length(),
                            "doc": enum_docs.get(name, {}).get(member.name, ""),
                        }
                        for member in value
                    ],
                }
            )
        elif callable(value):
            values.append(
                {
                    "name": name,
                    "kind": "function",
                    "signature": str(inspect.signature(value)),
                    "doc": " ".join((value.__doc__ or "").split()[:40]),
                }
            )
        elif isinstance(value, bytes):
            values.append(
                {
                    "name": name, "kind": "bytes",
                    "hex": value.hex(), "length": len(value),
                    "int_le": int.from_bytes(value, "little"),
                    "int_be": int.from_bytes(value, "big"),
                    "doc": docs.get(name, ""),
                }
            )
        elif isinstance(value, bool):
            continue
        elif isinstance(value, int):
            values.append(
                {
                    "name": name, "kind": "int", "value": int(value),
                    "doc": docs.get(name, ""),
                }
            )
        elif isinstance(value, str):
            values.append(
                {
                    "name": name, "kind": "str", "text": value,
                    "doc": docs.get(name, ""),
                }
            )

    return {
        "enums": enums,
        "values": values,
        # The version encoder demonstrated on real inputs rather than described.
        # The page shows what the function returned; it does not re-implement it.
        "fw_version_examples": [
            {
                "input": version,
                "encoded": C.encode_fw_version(version).hex(),
                "with_flag": C.with_maintenance_flag(
                    C.encode_fw_version(version)
                ).hex(),
            }
            for version in ("0.0.0", "1.2.0", "2.0.0", "2.0.1", "255.255.255")
        ],
    }


def module_level_docs(module: Any) -> Dict[str, str]:
    """`{NAME: docstring}` for module-level assignments, read from source."""
    tree = ast.parse(pathlib.Path(inspect.getfile(module)).read_text())
    out: Dict[str, str] = {}
    previous: Optional[str] = None
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
            previous = stmt.targets[0].id
        elif (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
            and previous is not None
        ):
            out[previous] = " ".join(stmt.value.value.split())
            previous = None
        else:
            previous = None
    return out


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
    # The only hand-written inverse in this file, checked against the model's
    # own encoder before anything is emitted.
    _check_version_roundtrip()
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



# --------------------------------------------------------------------------
# L1: the SPI transactions under an exchange
# --------------------------------------------------------------------------

@contextlib.contextmanager
def spi_capture(model: Tropic01Model):
    """Every chip-select low..high the host drives on `model`, MOSI and MISO.

    The host talks to the model through the same three calls a real SPI
    driver would make - `spi_drive_csn_low`, `spi_send`, `spi_drive_csn_high`
    (`tvl/host/low_level_communication.py`) - so wrapping those on the
    instance sees exactly what a logic analyser on the bus would.
    """
    log: List[Dict[str, Any]] = []
    current: Dict[str, bytes] = {}
    low, send, high = model.spi_drive_csn_low, model.spi_send, model.spi_drive_csn_high

    def csn_low() -> None:
        current.clear(); current["mosi"] = b""; current["miso"] = b""
        low()

    def spi_send(data: Any) -> Any:
        out = send(data)
        if current:
            current["mosi"] += bytes(data); current["miso"] += bytes(out)
        return out

    def csn_high() -> None:
        high()
        if current:
            mosi, miso = current["mosi"], current["miso"]
            log.append({
                "mosi": mosi.hex(), "miso": miso.hex(),
                "chip_status": miso[0] if miso else None,
                # What the host was doing: sending a frame, or polling for one.
                "kind": "poll" if mosi[:1] == bytes([L2IdFieldEnum.GET_RESP]) else "send",
            })
            current.clear()

    model.spi_drive_csn_low = csn_low  # type: ignore[method-assign]
    model.spi_send = spi_send  # type: ignore[method-assign]
    model.spi_drive_csn_high = csn_high  # type: ignore[method-assign]
    try:
        yield log
    finally:
        del model.spi_drive_csn_low, model.spi_send, model.spi_drive_csn_high


def frames_from_transactions(transactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The L2 frames under a list of SPI transactions: a `send` carries one
    request frame on MOSI; each following `poll` carries a response frame on
    MISO after the CHIP_STATUS byte, STATUS RSP_LEN DATA CRC16."""
    frames: List[Dict[str, Any]] = []
    for t in transactions:
        if t["kind"] == "send":
            frames.append({"request": t["mosi"], "responses": []})
        elif frames:
            miso = bytes.fromhex(t["miso"])[1:]
            if len(miso) >= 2:
                frames[-1]["responses"].append(miso[: 4 + miso[1]].hex())
    return frames


# --------------------------------------------------------------------------
# L3: the command set, its gates, and every command sent for real
# --------------------------------------------------------------------------

_HOST_PRIV = bytes(range(32))
_TROPIC_PRIV = bytes(range(32, 64))


def _x25519_pub(priv: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()


def paired_chip(r_config: Optional[Dict[str, int]] = None) -> Tuple[Tropic01Model, Host]:
    """A fresh chip in Application mode with the host's key in pairing slot 0,
    and a host that knows it. Same keys and pinned entropy as every other
    capture, so the bytes are reproducible."""
    host_pub, tropic_pub = _x25519_pub(_HOST_PRIV), _x25519_pub(_TROPIC_PRIV)
    model = Tropic01Model(
        debug_random_value=bytes(4), busy_iter=[False],
        s_t_priv=_TROPIC_PRIV, s_t_pub=tropic_pub,
        **({"r_config": ConfigurationObjectImpl.from_dict(r_config)} if r_config else {}),
    )
    model.i_pairing_keys[0].write(host_pub)
    model.power_on()
    host = Host(
        s_h_priv=[_HOST_PRIV], s_h_pub=[host_pub], s_t_pub=tropic_pub,
        pairing_key_index=0, debug_random_value=bytes(4),
    ).set_target(model)
    return model, host


def open_session(host: Host) -> int:
    """Handshake on slot 0; returns the L2 status. The host processes the
    response itself, so after this both sides hold the session keys."""
    response = host.send_request(
        TsL2HandshakeRequest(e_hpub=host.session.create_handshake_request(), pkey_index=0)
    )
    return int(response.status.value)


def l3_cases() -> List[Tuple[str, str, Dict[str, Any], Any, str, Optional[Dict[str, int]]]]:
    """(group, label, params, command, note, r_config) - every L3 command once,
    in an order where each finds the state the one before it left. r_config
    is None for the shared chip; a case with its own config gets its own chip."""
    L = l3_mod
    P256, ED = L.TsL3EccKeyGenerateCommand.CurveEnum.P256, L.TsL3EccKeyGenerateCommand.CurveEnum.ED25519
    key = bytes(range(1, 33))
    return [
        ("Ping", "loopback 5 bytes", {"DATA_IN": "hello"}, L.TsL3PingCommand(data_in=b"hello"),
         "The simplest L3 command: the chip echoes the bytes. Still gated by CFG_UAP_PING.", None),
        ("Random", "8 bytes", {"N_BYTES": 8}, L.TsL3RandomValueGetCommand(n_bytes=8),
         "Pinned entropy, so the bytes are reproducible here; a real chip would differ.", None),
        ("Pairing key", "read slot 0 (the session's own key)", {"SLOT": 0}, L.TsL3PairingKeyReadCommand(slot=0), "", None),
        ("Pairing key", "write slot 1", {"SLOT": 1}, L.TsL3PairingKeyWriteCommand(slot=1, s_hipub=key),
         "OTP: a slot is written once.", None),
        ("Pairing key", "read slot 1 (just written)", {"SLOT": 1}, L.TsL3PairingKeyReadCommand(slot=1), "", None),
        ("Pairing key", "invalidate slot 1", {"SLOT": 1}, L.TsL3PairingKeyInvalidateCommand(slot=1),
         "Irreversible: the slot can never be written again.", None),
        ("Pairing key", "read slot 3 (blank)", {"SLOT": 3}, L.TsL3PairingKeyReadCommand(slot=3), "", None),
        ("R-config", "read CFG_START_UP (0x000)", {"ADDRESS": "0x000"}, L.TsL3RConfigReadCommand(address=0x000), "", None),
        ("R-config", "write CFG_SLEEP_MODE (0x018) = 0xFFFFFFFE", {"ADDRESS": "0x018", "VALUE": "0xFFFFFFFE"},
         L.TsL3RConfigWriteCommand(address=0x018, value=0xFFFFFFFE),
         "Clears SLEEP_MODE_EN in R-config. Takes effect at the next boot - the running chip keeps its latch.", None),
        ("R-config", "read CFG_SLEEP_MODE (0x018) back", {"ADDRESS": "0x018"}, L.TsL3RConfigReadCommand(address=0x018),
         "Memory shows the write; the latch the chip runs on does not, until a reboot.", None),
        ("R-config", "erase", {}, L.TsL3RConfigEraseCommand(), "All 512 bytes back to 0xFF.", None),
        ("I-config", "read CFG_START_UP (0x000)", {"ADDRESS": "0x000"}, L.TsL3IConfigReadCommand(address=0x000), "", None),
        ("I-config", "write CFG_GPO (0x014) bit 0", {"ADDRESS": "0x014", "BIT_INDEX": 0},
         L.TsL3IConfigWriteCommand(address=0x014, bit_index=0),
         "One bit, one direction: I-config only ever clears, and there is no erase.", None),
        ("User data", "write slot 0", {"UDATA_SLOT": 0, "DATA": "hello"}, L.TsL3RMemDataWriteCommand(udata_slot=0, data=b"hello"), "", None),
        ("User data", "read slot 0", {"UDATA_SLOT": 0}, L.TsL3RMemDataReadCommand(udata_slot=0), "", None),
        ("User data", "erase slot 0", {"UDATA_SLOT": 0}, L.TsL3RMemDataEraseCommand(udata_slot=0), "", None),
        ("ECC key", "generate Ed25519 in slot 0", {"SLOT": 0, "CURVE": "ED25519"},
         L.TsL3EccKeyGenerateCommand(slot=0, curve=ED), "", None),
        ("ECC key", "read slot 0 (public part)", {"SLOT": 0}, L.TsL3EccKeyReadCommand(slot=0),
         "Only the public key ever leaves the chip.", None),
        ("Sign", "EdDSA with slot 0", {"SLOT": 0, "MSG": "message"}, L.TsL3EddsaSignCommand(slot=0, msg=b"message"), "", None),
        ("ECC key", "store a P-256 key in slot 1", {"SLOT": 1, "CURVE": "P256"},
         L.TsL3EccKeyStoreCommand(slot=1, curve=P256, k=key), "", None),
        ("Sign", "ECDSA with slot 1", {"SLOT": 1, "MSG_HASH": "32 bytes"},
         L.TsL3EcdsaSignCommand(slot=1, msg_hash=bytes(range(32))), "", None),
        ("ECC key", "erase slot 1", {"SLOT": 1}, L.TsL3EccKeyEraseCommand(slot=1), "", None),
        ("Counter", "init counter 0 to 5", {"MCOUNTER_INDEX": 0, "MCOUNTER_VAL": 5},
         L.TsL3McounterInitCommand(mcounter_index=0, mcounter_val=5), "", None),
        ("Counter", "update counter 0", {"MCOUNTER_INDEX": 0}, L.TsL3McounterUpdateCommand(mcounter_index=0),
         "Monotonic means down only: 5 becomes 4.", None),
        ("Counter", "get counter 0", {"MCOUNTER_INDEX": 0}, L.TsL3McounterGetCommand(mcounter_index=0), "", None),
        ("Mac-and-Destroy", "slot 0", {"SLOT": 0, "DATA_IN": "32 bytes"},
         L.TsL3MacAndDestroyCommand(slot=0, data_in=bytes(range(32))),
         "The MAC is returned and the slot is destroyed in the same command - the PIN-attempt primitive.", None),
        # Refusals. A fresh chip each, with the R-config that forbids it.
        ("Ping", "refused: CFG_UAP_PING slot-0 privilege cleared", {"DATA_IN": "x"},
         L.TsL3PingCommand(data_in=b"x"),
         "UNAUTHORIZED from check_access_privileges: the session's pairing key has no right to this command.",
         {"cfg_uap_ping": 0xFFFFFF00}),
        ("Random", "refused: CFG_UAP_RANDOM_VALUE_GET slot-0 privilege cleared", {"N_BYTES": 4},
         L.TsL3RandomValueGetCommand(n_bytes=4), "", {"cfg_uap_random_value_get": 0xFFFFFF00}),
    ]


def _field_specs(cls: type) -> List[Dict[str, Any]]:
    """Every field declared on a message class - name, type, datafield
    parameters and the docstring under it - read from its source."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(cls)))
    body = tree.body[0].body  # type: ignore[attr-defined]
    out: List[Dict[str, Any]] = []
    for i, node in enumerate(body):
        if not (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)):
            continue
        params: Dict[str, Any] = {}
        if isinstance(node.value, ast.Call):
            for kw in node.value.keywords:
                try:
                    params[kw.arg or ""] = ast.literal_eval(kw.value)
                except Exception:
                    params[kw.arg or ""] = ast.unparse(kw.value)
        doc = ""
        nxt = body[i + 1] if i + 1 < len(body) else None
        if isinstance(nxt, ast.Expr) and isinstance(nxt.value, ast.Constant) and isinstance(nxt.value.value, str):
            doc = " ".join(nxt.value.value.split())
        typ = ast.unparse(node.annotation)
        size = {"U8Scalar": 1, "U16Scalar": 2, "U32Scalar": 4}.get(typ)
        if size is None and "size" in params:
            size = params["size"]
        out.append({"name": node.target.id, "type": typ, "size": size, "params": params, "doc": doc})
    return out


def l3_api() -> List[Dict[str, Any]]:
    """The 23 L3 commands: id, fields in and out, result codes, the handler,
    and the Configuration Object register that gates each - all read off the
    generated API module and the handler's source."""
    docs = attribute_docs(l3_mod)
    enum_docs = docs.get("L3Enum", {})
    commands = {c.ID: c for c in vars(l3_mod).values()
                if inspect.isclass(c) and issubclass(c, L3Command) and hasattr(c, "ID")}
    results = {c.ID: c for c in vars(l3_mod).values()
               if inspect.isclass(c) and issubclass(c, L3Result) and hasattr(c, "ID")}
    impl_cls = next(c for c in vars(l3_impl).values()
                    if inspect.isclass(c) and c.__module__ == l3_impl.__name__
                    and hasattr(c, "ts_l3_ping"))
    handlers: Dict[type, Any] = {}
    for name, fn in inspect.getmembers(impl_cls, inspect.isfunction):
        if name.startswith("ts_l3_"):
            hints = fn.__annotations__
            cmd_type = next((v for k, v in hints.items() if k != "return"), None)
            if cmd_type is not None:
                handlers[cmd_type] = fn
    out = []
    for member in sorted(L3Enum, key=lambda e: e.value):
        cmd, res = commands.get(member.value), results.get(member.value)
        fn = handlers.get(cmd) if cmd else None
        uap: List[Dict[str, Any]] = []
        line = None
        if fn is not None:
            fn = inspect.unwrap(fn)  # the meta-model wraps every handler
            src = inspect.getsource(fn); line = inspect.getsourcelines(fn)[1]
            for reg in sorted(set(re.findall(r"self\.config\.(cfg_uap_\w+)", src))):
                fields = sorted(set(re.findall(r"(?:config|self\.config\.%s)\.(\w+)" % reg, src)))
                uap.append({"register": reg.upper(), "fields": [f for f in fields if f != reg]})
        result_codes = {}
        if res is not None and hasattr(res, "ResultEnum"):
            result_codes = {m.name: int(m.value) for m in res.ResultEnum}
        out.append({
            "name": member.name, "id": int(member.value), "doc": enum_docs.get(member.name, ""),
            "command_class": cmd.__name__ if cmd else None,
            "result_class": res.__name__ if res else None,
            "command_fields": [f for f in _field_specs(cmd) if f["name"] != "id"] if cmd else [],
            "result_fields": [f for f in _field_specs(res) if f["name"] != "result"] if res else [],
            "result_codes": result_codes,
            "handler": fn.__name__ if fn else None, "handler_line": line,
            "uap": uap,
        })
    return out


def l3_exchanges() -> List[Dict[str, Any]]:
    """Every L3 command sent for real inside a secure session: the plaintext
    command and result, the L2 Encrypted_Cmd frames that carried them, and the
    SPI transactions under those. One chip for the sequence so state carries
    (a key generated, then read, then used); refusal cases get their own."""
    model, host = paired_chip(); open_session(host)
    out: List[Dict[str, Any]] = []
    for group, label, params, command, note, r_config in l3_cases():
        m, h = (model, host)
        if r_config is not None:
            m, h = paired_chip(r_config); open_session(h)
        error = None
        with spi_capture(m) as transactions:
            try:
                result = h.send_command(command)
            except Exception as exc:  # a command that raises is worth showing
                result, error = None, f"{type(exc).__name__}: {exc}"
        frames = frames_from_transactions(transactions)
        code = int(result.result.value) if result is not None else None
        # A non-OK result is parsed as a generic DefaultL3Result, so the
        # command-specific codes live on the result class the command *would*
        # have produced - look that up by CMD_ID, then fall back to the common ones.
        expected = next((c for c in vars(l3_mod).values() if inspect.isclass(c)
                         and issubclass(c, L3Result) and getattr(c, "ID", None) == command.ID), None)
        name = None
        if code is not None:
            for enum in (getattr(expected, "ResultEnum", None), L3ResultFieldEnum):
                try:
                    name = enum(code).name if enum else None  # type: ignore[misc]
                except ValueError:
                    continue
                if name:
                    break
        out.append({
            "layer": "L3", "mode": "APPLICATION", "group": group, "label": label, "params": params,
            "command_class": type(command).__name__, "command_id": int(command.ID),
            "result_class": type(result).__name__ if result is not None else None,
            "command": command.to_bytes().hex(),
            "result": result.to_bytes().hex() if result is not None else None,
            "result_code": code, "result_name": name, "error": error,
            "repr_command": str(command), "repr_result": str(result) if result is not None else "",
            "l2_frames": frames, "transactions": transactions,
            "chip_status_after": read_chip_status(m), "note": note,
            "own_chip": r_config is not None,
        })
    return out


# --------------------------------------------------------------------------
# Memory: what the chip keeps, in how many slots, and who touches it
# --------------------------------------------------------------------------

def memory_map() -> Dict[str, Any]:
    """The chip's storage as the model holds it. Slot counts come from the UAP
    registers' field names (`gen_ecckey_slot_24_31` ⇒ 32 slots), sizes from
    the partition modules' constants."""
    regs = {r["name"]: r for r in co_registers()}

    def slots_of(register: str) -> int:
        upper = 0
        for f in regs[register]["fields"]:
            m = re.search(r"_(\d+)_(\d+)$", f["name"])
            if m:
                upper = max(upper, int(m.group(2)))
        return upper + 1

    partitions = [
        {"name": "Pairing key slots", "memory": "I", "attr": "i_pairing_keys",
         "slots": S_HI_PUB_NB_SLOTS, "slot_size": f"{pairing_mod.KEY_SIZE} B (X25519 public key)",
         "commands": {"write": ["PAIRING_KEY_WRITE"], "read": ["PAIRING_KEY_READ"], "erase": ["PAIRING_KEY_INVALIDATE"]},
         "note": "blank → written → invalidated, never back; slot 0 is provisioned by Tropic Square"},
        {"name": "I-config", "memory": "I", "attr": "i_config", "slots": 128, "slot_size": "4 B register",
         "commands": {"write": ["I_CONFIG_WRITE"], "read": ["I_CONFIG_READ"], "erase": []},
         "note": "one bit per write, 1→0 only, no erase - the floor the chip can never rise above"},
        {"name": "R-config", "memory": "R", "attr": "r_config", "slots": 128, "slot_size": "4 B register",
         "commands": {"write": ["R_CONFIG_WRITE"], "read": ["R_CONFIG_READ"], "erase": ["R_CONFIG_ERASE"]},
         "note": "the adjustable layer; the chip runs on i_config & r_config, latched at boot"},
        {"name": "User data", "memory": "R", "attr": "r_user_data",
         "slots": slots_of("CFG_UAP_R_MEM_DATA_WRITE"), "slot_size": f"up to {udata_mod.SLOT_SIZE_BYTES} B",
         "commands": {"write": ["R_MEM_DATA_WRITE"], "read": ["R_MEM_DATA_READ"], "erase": ["R_MEM_DATA_ERASE"]},
         "note": "general-purpose secure storage"},
        {"name": "ECC key slots", "memory": "R", "attr": "r_ecc_keys",
         "slots": slots_of("CFG_UAP_ECC_KEY_GENERATE"), "slot_size": "32 B private key + curve + origin",
         "commands": {"write": ["ECC_KEY_GENERATE", "ECC_KEY_STORE"], "read": ["ECC_KEY_READ (public part only)"],
                      "erase": ["ECC_KEY_ERASE"], "use": ["ECDSA_SIGN", "EDDSA_SIGN"]},
         "note": "the private key never leaves the chip; signing happens inside"},
        {"name": "Monotonic counters", "memory": "R", "attr": "r_mcounters",
         "slots": slots_of("CFG_UAP_MCOUNTER_INIT"), "slot_size": f"{mcounter_mod.MCOUNTER_SIZE}-bit",
         "commands": {"write": ["MCOUNTER_INIT"], "read": ["MCOUNTER_GET"], "erase": [], "use": ["MCOUNTER_UPDATE (decrements)"]},
         "note": "down only; a PIN-attempt counter that cannot be reset by the host without re-init rights"},
        {"name": "Mac-and-Destroy slots", "memory": "R", "attr": "r_macandd_data",
         "slots": slots_of("CFG_UAP_MAC_AND_DESTROY"), "slot_size": f"{mad_mod.MACANDD_DATA_INPUT_LEN} B",
         "commands": {"write": [], "read": [], "erase": [], "use": ["MAC_AND_DESTROY (returns the MAC, destroys the slot)"]},
         "note": "one-shot secrets"},
        {"name": "Firmware banks", "memory": "R", "attr": "fw_banks", "slots": len(FwBankIdEnum),
         "slot_size": f"{FW_HEADER_SIZE}-byte header (the model holds headers, not images)",
         "commands": {"write": ["Mutable_FW_Update (bootloader only; not modelled)"], "read": ["Get_Info(FW_BANK), Start-up mode only"], "erase": []},
         "note": "two per firmware so an update goes to the inactive bank first"},
        {"name": "Identity", "memory": "I", "attr": "chip_id, x509_certificate",
         "slots": 1, "slot_size": f"{CHIP_ID_SIZE} B chip ID; {CERTIFICATE_SIZE} B certificate store",
         "commands": {"write": [], "read": ["Get_Info(CHIP_ID), Get_Info(X509_CERTIFICATE) - both modes"], "erase": []},
         "note": "provisioned at the fab; never changes"},
    ]
    volatile = [
        {"name": "Secure session", "attr": "session", "cleared_by": "invalidate_session()"},
        {"name": "L3 command buffer", "attr": "command_buffer", "cleared_by": "command_buffer.reset()"},
        {"name": "SPI state machine + response buffer", "attr": "spi_fsm", "cleared_by": "spi_fsm.reset()"},
        {"name": "Configuration latch (i & r)", "attr": "_config", "cleared_by": "_config = None, re-read at boot"},
    ]
    return {"partitions": partitions, "volatile": volatile,
            "reset_note": "Both reboots clear exactly the volatile list; every partition survives both."}


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
        "constants": constants(),
        "boot_transitions": boot_transitions(),
        "walkthroughs": call_traces(),
        "wire_traces": wire_traces(),
        "exchanges": exchanges(),
        "l3_api": l3_api(),
        "l3_exchanges": l3_exchanges(),
        "memory": memory_map(),
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
        f"{len(spec['walkthroughs']['scenarios'])} walkthroughs, "
        f"{len(spec['wire_traces'])} traces, "
        f"{len(spec['exchanges'])} exchanges, "
        f"{len(spec['l3_api'])} L3 commands, {len(spec['l3_exchanges'])} L3 exchanges"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
