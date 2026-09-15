#!/usr/bin/env python3
"""A guided, runnable tour of the TROPIC01 model.

    cd ts-tvl && python3 /path/to/tour.py

Text prints immediately; it pauses between steps so output does not scroll past.
    --no-pause   do not wait for Enter
    --fast       no pauses at all (for piping to a file or a pager)
    --flow       reveal text gradually, and type the wire bytes out one by one

Sixteen steps. Each sends real data to the model and takes the reply apart
piece by piece, so you can watch the thing work rather than read about it.

WHO THIS IS FOR: someone clever who is not an embedded engineer. Every piece of
jargon is explained the first time it appears, in proportion to how far it sits
from ordinary knowledge - a phrase for the near ones, a paragraph for the genuinely
specialist ones. Nothing is assumed.

Steps 0-10 are the chip-mode feature built here.
Steps 11-15 are parts of the chip that feature did NOT touch, so that no part of
the system stays a black box.

The source is meant to be read next to its output.
"""

import argparse
import os
import re
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tvl.api.l2_api import (
    L2Enum,
    TsL2GetInfoRequest,
    TsL2HandshakeRequest,
    TsL2StartupRequest,
)
from tvl.api.l3_api import TsL3PingCommand, TsL3RandomValueGetCommand
from tvl.constants import (
    L1ChipStatusFlag,
    L2IdFieldEnum,
    L2StatusEnum,
    L3ResultFieldEnum,
)
from tvl.host.host import Host
from tvl.targets.model.configuration_object_impl import ConfigurationObjectImpl
from tvl.targets.model.internal.pairing_keys import PairingKeys
from tvl.targets.model.tropic01_model import Tropic01Model

OID = TsL2GetInfoRequest.ObjectIdEnum
STARTUP = TsL2StartupRequest.StartupIdEnum

BOLD, CYAN, DIM, GREEN, YELLOW, OFF = (
    "\033[1m", "\033[36m", "\033[2m", "\033[32m", "\033[33m", "\033[0m"
)

# --- pacing ------------------------------------------------------------------
_ap = argparse.ArgumentParser(add_help=True, description=__doc__)
_ap.add_argument("--flow", action="store_true",
                 help="reveal text gradually instead of printing it at once")
_ap.add_argument("--no-pause", action="store_true",
                 help="do not wait for Enter between steps")
_ap.add_argument("--fast", action="store_true",
                 help="no pauses at all - for piping to a file or a pager")
_ap.add_argument("--speed", type=float, default=1.0,
                 help="only affects --flow. 2.0 = twice as fast")
ARGS = _ap.parse_args()

TTY = sys.stdout.isatty()
# Text prints instantly by default. Gradual reveal is opt-in via --flow, because
# waiting for prose to appear is distracting once you know what it says.
PACED = ARGS.flow and not ARGS.fast and TTY
# Pausing between steps is NOT the same thing - it stops a wall of output
# scrolling past. On by default in a terminal, off when piping.
WAIT_FOR_KEY = TTY and not ARGS.fast and not ARGS.no_pause


def _sleep(seconds: float) -> None:
    if PACED:
        time.sleep(seconds / max(ARGS.speed, 0.01))


def reveal(text: str, delay: float = 0.022) -> None:
    """Print prose a line at a time, so it can be read as it arrives."""
    for line in text.split("\n"):
        print(line, flush=True)
        if line.strip():
            _sleep(delay + min(len(line), 90) * 0.0016)
        else:
            _sleep(delay * 0.5)


def type_bytes(prefix: str, data: bytes, limit: int = 24) -> None:
    """Print the bytes. Under --flow, one at a time, to watch the wire fill."""
    if not PACED:
        print(prefix + hexs(data, limit) + OFF, flush=True)
        return
    shown = data[:limit]
    sys.stdout.write(prefix)
    sys.stdout.flush()
    for b in shown:
        sys.stdout.write(f"{b:02x} ")
        sys.stdout.flush()
        _sleep(0.012)
    if len(data) > limit:
        sys.stdout.write(f" ...(+{len(data) - limit} more)")
    print(OFF, flush=True)
    _sleep(0.12)


def pause(prompt: str = "press Enter to continue") -> None:
    if WAIT_FOR_KEY:
        try:
            input(f"{DIM}      -- {prompt} --{OFF}")
        except EOFError:
            pass
    else:
        _sleep(0.5)


# --- linking the tour to the real source -------------------------------------
REPO = Path(os.environ.get("TSTVL", ".")).resolve()


def source(relpath: str, pattern: str, lines: int = 6, why: str = "") -> None:
    """Print the ACTUAL lines from the repository that the last step exercised.

    This is not illustrative text - it is read off disk at run time. If the code
    changes, this output changes with it.
    """
    f = REPO / relpath
    if not f.exists():
        print(f"   {DIM}(source not found: {f} - run from the ts-tvl checkout,"
              f" or set TSTVL=/path/to/ts-tvl){OFF}")
        return
    text = f.read_text().splitlines()
    idx = next((i for i, ln in enumerate(text) if re.search(pattern, ln)), None)
    if idx is None:
        print(f"   {DIM}(pattern {pattern!r} not found in {relpath}){OFF}")
        return
    ev = _mark("source", file=relpath, line=idx + 1, why=why,
               lines=text[idx : min(idx + lines, len(text))])
    print(f"\n   {GREEN}the real code that just ran{OFF}"
          f"  {DIM}{relpath}:{idx + 1}{OFF}" + (f"\n   {DIM}{why}{OFF}" if why else ""))
    for i in range(idx, min(idx + lines, len(text))):
        print(f"   {DIM}{i + 1:>4}|{OFF} {YELLOW}{text[i]}{OFF}")
        _sleep(0.02)
    _done(ev)

# --- setting up a chip as the factory would leave it ------------------------
# A real chip ships carrying two secrets: its own private key, and the
# customer's public key written into one of four "pairing key" slots.
#
# PUBLIC / PRIVATE KEY, if that is not familiar: a matched pair of very large
# numbers. You publish one and keep the other secret. Anything they are used for
# works because only the holder of the private half can perform the matching
# half of the maths, and you cannot work backwards from public to private.
T_PRIV = X25519PrivateKey.generate()   # the chip's private key; never leaves it
H_PRIV = X25519PrivateKey.generate()   # the host computer's private key
SLOT = 0                               # which of the four pairing slots we use

# busy_iter=[False] switches off a deliberate quirk: by default the model
# randomly pretends to be busy, imitating a real chip that is sometimes not
# ready. Left on, this tour would print something different every run.
model = Tropic01Model(
    busy_iter=[False],
    chip_id=b"\xA1" * 128,
    s_t_priv=T_PRIV.private_bytes_raw(),
    s_t_pub=T_PRIV.public_key().public_bytes_raw(),
    i_pairing_keys=PairingKeys.from_dict(
        {SLOT: {"value": H_PRIV.public_key().public_bytes_raw(), "state": "written"}}
    ),
)

# The "host" is the computer talking to the chip - in real life a phone or a
# hardware wallet. Here it is a reference implementation shipped with ts-tvl.
host = Host(
    s_h_priv=[H_PRIV.private_bytes_raw()] * 4,
    s_h_pub=[H_PRIV.public_key().public_bytes_raw()] * 4,
    s_t_pub=T_PRIV.public_key().public_bytes_raw(),
    pairing_key_index=SLOT,
).set_target(model)

# A "wire tap": quietly record everything crossing between host and chip, so we
# can later show the encrypted traffic exactly as it appears.
TAP: list = []
_real_spi_send = model.spi_send

# A structured log of what the tour did, beside the prose it printed, so a
# renderer can show the same run in its own format. Each entry records where
# in stdout its printed form starts and ends.
EVENTS: list = []


def _mark(kind: str, **fields) -> dict:
    try:
        at = sys.stdout.tell()
    except (AttributeError, OSError, ValueError):
        at = None
    ev = {"kind": kind, "at": at, "end": None, **fields}
    EVENTS.append(ev)
    return ev


def _done(ev: dict) -> None:
    try:
        ev["end"] = sys.stdout.tell()
    except (AttributeError, OSError, ValueError):
        ev["end"] = None


def _tapped(data: bytes) -> bytes:
    out = _real_spi_send(data)
    TAP.append((bytes(data), bytes(out)))
    return out


model.spi_send = _tapped  # type: ignore[method-assign]

step_no = -1


def step(title: str, explain: str = "") -> None:
    global step_no
    if step_no >= 0:
        pause("Enter for the next step")
    step_no += 1
    ev = _mark("step", n=step_no, title=title, explain=explain.strip("\n"))
    print(f"\n{BOLD}{'=' * 76}\n {step_no}. {title}\n{'=' * 76}{OFF}", flush=True)
    _sleep(0.3)
    if explain:
        reveal(explain.strip("\n") + "\n")
        _sleep(0.3)
    _done(ev)


def note(text: str) -> None:
    ev = _mark("note", text=text.strip("\n"))
    _sleep(0.35)
    reveal(CYAN + "\n".join("      " + ln for ln in text.strip("\n").split("\n")) + OFF)
    _done(ev)


def hexs(b: bytes, limit: int = 24) -> str:
    return b[:limit].hex(" ") + (f"  ...(+{len(b) - limit} more)" if len(b) > limit else "")


def txn(payload: bytes) -> bytes:
    """One complete exchange over the wire between host and chip."""
    model.spi_drive_csn_low()      # "I am about to talk to you"
    out = model.spi_send(payload)  # data travels both directions at once
    model.spi_drive_csn_high()     # "I have finished"
    return out


def chip_status() -> int:
    """Ask only "what state are you in?" - the shortest possible exchange."""
    return txn(bytes([L2IdFieldEnum.GET_RESP]))[0]


def show_status(prefix: str = "") -> int:
    s = chip_status()
    bits = []
    if s & L1ChipStatusFlag.READY:
        bits.append("READY")
    if s & L1ChipStatusFlag.ALARM:
        bits.append("ALARM")
    if s & L1ChipStatusFlag.START:
        bits.append("START")
    mode = "MAINTENANCE / Start-up" if s & L1ChipStatusFlag.START else "APPLICATION"
    ev = _mark("status", value=s, mode=mode, prefix=prefix.strip())
    _sleep(0.25)
    print(f"   {prefix}CHIP_STATUS = {s:#04x}  [{' '.join(bits) or 'none set'}]"
          f"   -> the host reads this as: {mode}", flush=True)
    _sleep(0.2)
    _done(ev)
    return s


def decode_request(raw: bytes) -> None:
    """Take an outgoing message apart: ID | LENGTH | CONTENT | CHECKSUM."""
    req_id, req_len = raw[0], raw[1]
    data, crc = raw[2 : 2 + req_len], raw[2 + req_len :]
    try:
        name = L2Enum(req_id).name
    except ValueError:
        name = "?"
    type_bytes(f"   {DIM}we send:      ", raw)
    _sleep(0.2)
    print(f"      meaning:   ID={req_id:#04x} (\"{name}\")   LENGTH={req_len}"
          f"   CONTENT=[{data.hex(' ') or 'nothing'}]   CHECKSUM={crc.hex()}", flush=True)
    _sleep(0.25)


def decode_response(resp: bytes) -> bytes:
    """Take an incoming message apart: STATE | VERDICT | LENGTH | CONTENT | CHECKSUM."""
    status_byte, status, rsp_len = resp[0], resp[1], resp[2]
    data = resp[3 : 3 + rsp_len]
    crc = resp[3 + rsp_len : 5 + rsp_len]
    try:
        name = L2StatusEnum(status).name
    except ValueError:
        name = "?"
    _sleep(0.3)
    print(f"   chip replies: CHIP_STATUS={status_byte:#04x}   "
          f"VERDICT={status:#04x} (\"{name}\")   LENGTH={rsp_len}   "
          f"CHECKSUM={crc.hex()}", flush=True)
    if data:
        _sleep(0.15)
        type_bytes("      CONTENT: ", data)
    return data


def request(req, comment: str = "") -> bytes:
    """Send one message and collect the reply - which takes two exchanges."""
    raw = req.to_bytes()
    ev = _mark("exchange", sent=raw.hex())
    decode_request(raw)
    txn(raw)                                                 # exchange 1: ask
    resp = txn(bytes([L2IdFieldEnum.GET_RESP]) + bytes(140))  # exchange 2: collect
    data = decode_response(resp)
    ev["chip_status"] = resp[0]
    ev["got"] = resp[1 : 5 + resp[2]].hex()   # STATUS RSP_LEN DATA CRC, after the CHIP_STATUS byte
    _done(ev)
    if comment:
        note(comment)
    return data


def get_info(object_id: int, block_index: int = 0, comment: str = "") -> bytes:
    return request(TsL2GetInfoRequest(object_id=object_id, block_index=block_index), comment)


# ============================================================================

step(
    "How to read everything below",
    """
Four ideas, and the rest of this becomes legible.

(a) BYTES AND HEX. All communication is bytes - whole numbers from 0 to 255.
    They are written in hexadecimal (base 16) and marked with "0x": 0x01 is one,
    0x0A is ten, 0xFF is 255. Two hex digits is always exactly one byte. So
    "01 02 02 00 2b 98" is six bytes.

(b) THE WIRE. Host and chip are joined by a few physical wires, a scheme called
    SPI. One wire is a metronome supplied by the host; the chip cannot start a
    conversation, only answer one. The host pulls a "chip select" wire low
    meaning "I am talking to you now", trades bytes, then releases it. Call that
    one EXCHANGE. Bytes travel BOTH WAYS AT ONCE, so to receive anything the
    host must send filler and look at what comes back in return.

(c) ONE QUESTION TAKES TWO EXCHANGES. The first delivers the question; the chip
    has not answered yet, so it returns filler. The host then opens a second
    exchange starting with the byte 0xAA, meaning "give me the response now".
    Remember this - it is why several steps below happen in two beats.

(d) MESSAGE SHAPE.
        we send:      ID | LENGTH | CONTENT... | CHECKSUM
        chip replies: CHIP_STATUS | VERDICT | LENGTH | CONTENT... | CHECKSUM

    A CHECKSUM is a short number computed from the message contents. If a bit
    were corrupted in transit, the receiver's recomputed value would not match
    and it knows to ask again.

    CHIP_STATUS is special: it is the FIRST byte the chip returns in EVERY
    exchange, before you have asked anything at all. It is the chip continuously
    announcing its own state. A byte holds eight binary digits, or "bits", and
    three of them matter here:
        0x01 READY   ready for a question, or an answer is waiting
        0x02 ALARM   tampering detected
        0x04 START   the bootloader is running (explained in the next step)
""",
)

step(
    "A fresh chip has booted its application firmware",
    """
FIRMWARE is software living inside a device rather than on a computer's disk.
TROPIC01 carries two separate firmwares:

  - The BOOTLOADER, burned permanently into the chip during manufacture and
    impossible to change afterwards. It runs first after every restart, and its
    only jobs are to load the other firmware or to replace it with an update.
  - The APPLICATION firmware, held in rewritable memory and therefore
    updatable. This is the one that does the actual security work.

Only one runs at a time, and whichever it is decides what the chip will answer.
The host discovers which from a single bit.
""",
)
show_status()
print(f"   internally the model calls this: {model.chip_mode.name}")
note("""START is 0, so the application firmware is in charge.

A vocabulary warning, because three names exist for two things. The chip's
datasheet calls the bootloader state "Start-up mode". The host library calls it
"Maintenance mode". The assignment brief used both. They are all one single
state - there is one START bit and no room for a third possibility.""")

step(
    "Ask the application firmware which version it is",
    """
"Get_Info" is the general-purpose question. It carries an OBJECT_ID naming which
piece of information you want. Object 0x02 means "your RISC-V firmware version"
- RISC-V being the small general-purpose processor inside the chip.

Watch the CONTENT of the reply. You will send this identical question again
later and receive a different answer.
""",
)
app_version = get_info(
    OID.RISCV_FW_VERSION,
    comment="""The reply is 00 00 00 02. Read it BACKWARDS: version 2.0.0.

This convention is called LITTLE-ENDIAN - writing the least significant part
first, as if "two thousand and thirteen" were spoken "thirteen, two-thousand".
It is arbitrary but universal here, and it catches people constantly: a value
printed as 0x80000000 in a document appears on the wire as 00 00 00 80, never
80 00 00 00.""",
)

step(
    "Ask for a firmware bank header - and get turned down",
    """
The chip keeps its updatable firmware in four BANKS: two for the main processor
and two for a specialised coprocessor. Two of each, so an update can be written
into the spare and only switched over once it is complete and verified. A power
cut mid-update therefore cannot leave the chip unusable.

Object 0xB0 asks to read a bank's header - its version, size and fingerprint.
""",
)
get_info(
    OID.FW_BANK,
    1,
    comment="""Turned down, with the verdict "generic error".

Reading a bank means reading the very memory the running firmware is executing
from - rather like trying to read a page of the book somebody is currently
reading aloud from. Only the bootloader, which has not yet handed over control,
can do it safely.

Note that this is a generic error and NOT "unknown request". The QUESTION is
perfectly valid here; it is this particular OBJECT_ID the running firmware does
not serve. That distinction becomes important shortly.""",
)

step(
    "Ask the chip to restart into the bootloader - and watch what does NOT happen",
    """
"Startup_Req" restarts the chip. It carries one number saying how:
    0x01 REBOOT              restart normally, loading the application firmware
    0x03 MAINTENANCE_REBOOT  restart but STAY in the bootloader

Before this piece of work the model treated those two identically. That was the
bug being fixed.

Now a line from the datasheet that is easy to skim past:

    "TROPIC01 responds to Startup_Req by a regular L2 Response frame.
     TROPIC01 restarts only after Host MCU reads this L2 Response frame."

In plain English: the chip replies FIRST, and only restarts once you have
actually collected that reply.
""",
)
request(TsL2StartupRequest(startup_id=STARTUP.MAINTENANCE_REBOOT))
print(f"\n   internal mode is still: {model.chip_mode.name}   <- has not restarted!")
source("tvl/targets/model/tropic01_l2_api_impl.py", r"def ts_l2_startup", 22,
       why="the handler that just ran - note schedule_reboot, not reboot")
note("""The chip has ANSWERED but not yet RESTARTED. We have just collected the
answer, so the restart is now armed and will happen at the start of the next
exchange.

Why this matters concretely: remember CHIP_STATUS rides along with every reply.
If the chip restarted immediately, the CHIP_STATUS attached to THIS reply would
already announce the new mode, whereas a real chip still announces the old one.

An implementation that gets this wrong passes every test in the suite and is
still wrong against the datasheet. It is exactly the class of detail that only
reading the specification catches - and I got it wrong first time by not
reading it.""")

step(
    "The next exchange: the restart lands",
    "This is precisely what the host library does next - it asks for CHIP_STATUS.",
)
show_status()
print(f"   internal mode is now:   {model.chip_mode.name}")
source("tvl/targets/model/internal/chip_mode.py", r"def chip_status_flags", 12,
       why="the mode turns itself into the CHIP_STATUS bits you just saw")
note("""START flipped from 0 to 1.

That single bit is the ENTIRE agreement between chip and host about which
firmware is running. The host library reads this one byte and nothing else: if
ALARM is set, alarm; otherwise if READY and START are both set, the bootloader;
otherwise the application. There is no second signal and no negotiation.""")

step(
    "Send the identical question from step 2 - a different firmware answers",
    "Byte for byte the same message. Compare this reply against step 2's.",
)
boot_version = get_info(OID.RISCV_FW_VERSION)
source("tvl/targets/model/tropic01_l2_api_impl.py", r"def _riscv_fw_version", 14,
       why="why the same question gave a different answer")
v = boot_version
print(f"\n   step 2 said (application firmware) : {app_version.hex(' ')}")
print(f"   now it says (bootloader)           : {boot_version.hex(' ')}")
print(f"   the host reads that as version     : "
      f"{v[3] & 0x7F}.{v[2]}.{v[1]}   (plus a marker bit)")
note("""Two separate things changed.

First, the version is 2.0.1 rather than 2.0.0 - the bootloader's OWN version, a
genuinely different piece of software with its own release history.

Second, the top bit of the last byte is set: 0x82 rather than 0x02. (0x82 is
0x02 plus 0x80. Since a byte's eight bits carry the values 1, 2, 4 ... 128, the
0x80 bit is the highest of them - hence "most significant bit". Setting it flags
the answer without disturbing the version number underneath, which is why the
host strips it off with & 0x7F before reading the version.)

This is the most important observation in the tour. The reason the answer
differs is not an if-statement bolted onto a function. It is that A DIFFERENT
PROGRAM IS ANSWERING. Hold onto that picture - everything else follows from it.

One honest caveat, worth being able to say aloud: that top-bit convention
appears in NO published document, neither datasheet nor API specification. It is
visible only in the host library's test code.""")

step(
    "The coprocessor's version is a placeholder here",
    """
SPECT is a second, specialised processor inside the chip that performs
elliptic-curve mathematics - the heavy lifting behind digital signatures. In
bootloader mode it has no firmware loaded at all, so there is genuinely no
version for it to report.
""",
)
get_info(
    OID.SPECT_FW_VERSION,
    comment="""The API specification says, word for word: "The SPECT bootloader
is a part of RISC-V bootloader. Returns dummy value."

So this is a fixed placeholder rather than a computed version: the number
0x80000000, which little-endian renders as 00 00 00 80. The host library
compares against exactly those four bytes, and that single comparison is how its
test decides which mode the chip is in.""",
)

step(
    "Firmware bank headers - readable now the bootloader is in charge",
    """
The same object 0xB0 that was refused back in step 3. Which bank you want
travels in the second field, the one documented as "ignored" for version
queries. Reusing a spare field like that is normal in tightly-packed protocols.
""",
)
for bank_id, label in (
    (0x01, "main processor, bank 1"),
    (0x02, "main processor, bank 2"),
    (0x11, "coprocessor,    bank 1"),
    (0x12, "coprocessor,    bank 2"),
):
    print(f"\n   {label}  (id {bank_id:#04x})")
    data = get_info(OID.FW_BANK, bank_id)
    print("      -> " + ("52 bytes: a header, so this bank holds firmware"
                         if data else "0 bytes: this bank is EMPTY"))
note("""Exactly three reply lengths are legal: 52 bytes (this bootloader's header
layout), 20 (an older chip revision's), and 0 (an empty bank). The host library
rejects anything else outright, so this is not a place to improvise.

One genuine open question, worth raising with them: the host library accepts 0,
but the written API specification says a Get_Info reply is 1 to 128 bytes -
minimum one. Those two contradict each other. This model follows the library.""")

step(
    "The gate: try to open a secure conversation while in bootloader mode",
    """
This is the heart of the whole piece of work.

The bootloader is not the application firmware with features switched off. It is
a DIFFERENT and SMALLER set of questions it can understand. It has never heard
of the question "let us open a secure conversation" (ID 0x02).
""",
)
source("tvl/targets/model/tropic01_l2_api_impl.py", r"^L2_REQUEST_MODES", 28,
       why="the entire gating policy - eight lines of table, one comment each")
source("tvl/targets/model/base_model.py", r"def _is_request_available", 14,
       why="and this is the only place it is enforced, for every request")
request(
    TsL2HandshakeRequest(e_hpub=bytes(32), pkey_index=0),
    comment=""""Unknown request" - and the datasheet specifies exactly this:
"Upon receiving Handshake_Req, respond with STATUS=UNKNOWN_REQ".

Why not "temporarily disabled"? Because that would mean the feature exists and
has been switched off, which is what a different question returns when logging
is disabled by configuration. Nothing is switched off here. The question simply
is not in this program's vocabulary, and "I do not know that word" is the honest
answer.

And because this handshake is the ONLY way to open a secure conversation, and
"send an encrypted command" is blocked too, the ENTIRE encrypted command layer
becomes unreachable without a single line of code at that layer. That is why
there is no second list of blocked commands: a second list could drift out of
agreement with the first, and then the two would disagree silently.""",
)

step(
    "Restart back into the application firmware - the gate lifts",
    "The same two-beat dance: reply first, restart on the following exchange.",
)
request(TsL2StartupRequest(startup_id=STARTUP.REBOOT))
show_status()
get_info(OID.RISCV_FW_VERSION, comment="Back to the application firmware's version.")

# ============================================================================
# From here: parts of the chip this piece of work did NOT touch.
# ============================================================================

step(
    "Opening a secure conversation, for real",
    """
Everything so far travelled in plain sight - anyone with a probe on those wires
could read it. That is fine for "which version are you". It is not fine for
"sign this transaction".

So the real work happens inside an encrypted conversation, and the HANDSHAKE is
the only door into it. A handshake is the opening ritual in which two parties
prove who they are and agree on a shared secret key without ever transmitting
that key.

The recipe used here is a published, peer-reviewed one called Noise KK1:
  - X25519 to agree the shared secret,
  - AES-GCM to encrypt each message and make tampering detectable,
  - SHA-256 to boil the conversation so far down to a fixed-size fingerprint.

"KK" means both parties already know each other's public key beforehand - which
is our situation exactly: the chip's was set at the factory, ours sits in
pairing slot 0. Each side ALSO generates a single-use throwaway key pair for
this conversation alone. That is what makes recorded traffic undecipherable
later even if the long-term keys were somehow stolen afterwards.
""",
)
source("tvl/crypto/encrypted_session.py", r"PROTOCOL_NAME", 3,
       why="the recipe, named in the source - not something I inferred")
source("tvl/crypto/encrypted_session.py", r"def execute_handshake", 26,
       why="the handshake itself: the fingerprint, then three key agreements")
e_hpub = host.session.create_handshake_request()
print(f"   our throwaway public key  : {hexs(e_hpub, 16)}")
resp = host.send_request(
    TsL2HandshakeRequest(e_hpub=e_hpub, pkey_index=host.pairing_key_index)
)
print(f"   chip's verdict            : {resp.status.value:#04x} "
      f"(\"{L2StatusEnum(resp.status.value).name}\")")
print(f"   chip's throwaway pub key  : {hexs(resp.e_tpub.to_bytes(), 16)}")
print(f"   proof-of-identity tag     : {resp.t_tauth.to_bytes().hex(' ')}")
print(f"\n   secure conversation open?   chip says {model.session.is_session_valid()}, "
      f"host says {host.session.is_session_valid()}")
note("""What happened, in order:

  1. Both sides build a running fingerprint of everything said so far: the
     recipe's name, both long-term public keys, both throwaway public keys, and
     - importantly - WHICH PAIRING SLOT is in use. Baking the slot number in
     means a recorded handshake cannot be replayed against a different slot.

  2. Three key agreements are performed and stirred together. Each is a
     Diffie-Hellman exchange: a trick where two parties each combine their own
     private key with the other's public key and, remarkably, both arrive at the
     same secret number - while an eavesdropper who saw only the public halves
     cannot compute it. Doing it three times, mixing throwaway with long-term
     keys, is what binds the conversation to BOTH identities at once.

  3. Out of that stirring come two separate encryption keys, one per direction
     of travel, plus a third used only for the next step.

  4. The chip returns the "proof-of-identity tag": that third key applied to the
     conversation fingerprint. Our side recomputes it independently and
     compares. Only something holding the chip's genuine private key could have
     produced it, so a match proves we are talking to the real chip and not to
     an impostor sitting in the middle of the wire.""")

step(
    "Sending a command inside the secure conversation",
    """
Commands never cross the wire in the open. Each is encrypted, wrapped inside an
ordinary "here is an encrypted command" message, and if too long, chopped into
128-byte pieces and reassembled at the far end.

"Ping" simply echoes back whatever you send it, which makes it the cleanest
thing to watch happen.
""",
)
TAP.clear()
payload = b"hello tropic"
print(f"   what we want to send : Ping({payload!r})")
result = host.send_command(TsL3PingCommand(data_in=payload))
sent = [tx for tx, _ in TAP if tx and tx[0] == L2Enum.ENCRYPTED_CMD]
if sent:
    print("\n   what actually crossed the wire:")
    print(f"   {DIM}{hexs(sent[0], 28)}{OFF}")
print(f"\n   chip's answer        : {result.result.value:#04x} "
      f"(\"{L3ResultFieldEnum(result.result.value).name}\")")
print(f"   echoed back          : {result.data_out.to_bytes()!r}")
print(f"\n   message counters: outgoing={model.session.nonce_cmd}, "
      f"incoming={model.session.nonce_resp}")
note("""Search those wire bytes for "hello tropic" - it is not there. Neither is
the reply, which came back encrypted too and was unwrapped on our side.

Notice also that there are now TWO verdicts at two different levels: the outer
message said "received intact", and the inner command said "succeeded". They are
independent and can disagree - a perfectly delivered message can carry a command
that is refused, which is exactly what happens two steps from now.""")

step(
    "A second command, to watch the counters move",
    "Every command uses up exactly one counter value in each direction.",
)
result = host.send_command(TsL3RandomValueGetCommand(n_bytes=16))
print(f"   verdict: {result.result.value:#04x}   random bytes: "
      f"{result.random_data.to_bytes().hex(' ')}")
print(f"   message counters: outgoing={model.session.nonce_cmd}, "
      f"incoming={model.session.nonce_resp}")
note("""These counters are called NONCES - "numbers used once". This style of
encryption requires that no counter value is ever reused with the same key.
Reuse does not merely weaken it; it can hand an attacker the means to forge
messages outright.

So both sides track them in lockstep. If they ever disagree the chip abandons
the conversation immediately rather than guessing, because a mismatch means
somebody has dropped, replayed or injected a message. And when the counter
reaches its maximum - about four billion - the conversation is torn down rather
than allowed to wrap back to zero. Refusing to continue is the only safe move.""")

step(
    "Permissions: the same command, now refused",
    """
Every command the chip accepts begins with a permission check, and the answer
depends on WHICH PAIRING SLOT was used to open the conversation.

For each command the chip stores a small row of switches, one per slot. The
check is simply: "is the switch for the slot this conversation used turned on?"

We opened ours with slot 0, so switching off slot 0's permission for Ping revokes
it for us - and for nobody else.
""",
)
model.r_config = ConfigurationObjectImpl(cfg_uap_ping=0xFFFF_FFFE)
model._config = None
source("tvl/targets/model/base_model.py", r"def check_access_privileges", 30,
       why="the permission check every single command starts with")
result = host.send_command(TsL3PingCommand(data_in=b"nope"))
print(f"   chip's answer: {result.result.value:#04x} "
      f"(\"{L3ResultFieldEnum(result.result.value).name}\")")
note("""Refused as unauthorised. Now notice what did NOT happen: the secure
conversation is still open, and the command arrived and decrypted perfectly.

That is the difference between AUTHENTICATION - proving who you are, which the
handshake did - and AUTHORISATION, which is what you are permitted to do. Had we
opened the conversation using slot 1, slot 1's switch is still on and this
identical command would have worked.

Two further things this exposes:

  - Those switches live in configuration memory whose bits can only ever be
    turned OFF, never back on. That is what makes part of the chip's
    configuration "irreversible": the factory sets a ceiling which the field can
    lower but never raise. Deliberate, and unusual if you are used to ordinary
    software where any setting can be undone.

  - I had to clear a cached copy by hand for the change to take effect, because
    the chip reads its configuration once at power-on and remembers it. On a
    real chip you would have to restart it.""")

step(
    "Restarting ends the conversation - which is where we came in",
    "The persistence policy from the design note, demonstrated rather than asserted.",
)
model.r_config = ConfigurationObjectImpl()
model._config = None
print(f"   secure conversation before restart: {model.session.is_session_valid()}")
request(TsL2StartupRequest(startup_id=STARTUP.REBOOT))
show_status()
print(f"   secure conversation after restart : {model.session.is_session_valid()}")
source("tvl/targets/model/base_model.py", r"def _reset_volatile_state", 16,
       why="exactly what a restart clears - and the comment saying why")
source("tvl/targets/model/base_model.py", r"    def _boot", 34,
       why="THE state machine. Thirty lines. This is the whole feature.")
note("""Both kinds of restart wipe exactly this much and no more: the secure
conversation, the half-assembled command buffer, the wire-level state, and the
cached configuration.

Neither touches the configuration itself, the stored keys, saved user data, the
counters or the firmware banks. Those live in memory that survives loss of
power, and a restart does not erase memory.

The ONLY difference between the two restarts is whether the application firmware
gets loaded. The mode you end up in is a CONSEQUENCE of that, not a separate
decision - which is exactly why the code has one restart routine rather than
two.""")

print(f"\n{BOLD}{'=' * 76}\n What you just watched\n{'=' * 76}{OFF}")
print("""
  1. A "mode" does not switch features on and off - it decides WHICH PROGRAM
     answers. Two firmwares, not one firmware full of if-statements.

  2. One bit, START, carries that entire agreement. It rides on the first byte
     of every single exchange.

  3. The chip replies to a restart request, THEN restarts once you collect the
     reply. Two beats, and the datasheet is explicit about it.

  4. The identical question returns different bytes in the two modes, because a
     different program is answering.

  5. Refusing the handshake closes the whole encrypted layer by itself, with no
     code at that layer.

  6. The secure conversation follows a published recipe. The chip proves itself
     with a tag over a fingerprint that includes the pairing slot number.

  7. Every command checks the permission switch for the slot you paired with.
     Which slot you used IS your permission level.

  Now read two things, in this order. Together they are the whole feature:
     tvl/targets/model/tropic01_l2_api_impl.py -> L2_REQUEST_MODES  (an 8-row list)
     tvl/targets/model/base_model.py           -> _boot()           (30 lines)

  Then break it deliberately and re-run. This teaches far more than reading:
     - Delete the HANDSHAKE line from L2_REQUEST_MODES  -> step 9 stops refusing
     - Set busy_iter=[True] at the top of this file     -> READY starts flickering
     - Empty the dict in fw_bank.py:_default_banks()    -> step 8 changes
     - Change SLOT = 0 to SLOT = 1 at the top           -> step 14 stops refusing
""")
