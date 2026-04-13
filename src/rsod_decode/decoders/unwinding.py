"""Stack dump parsing and frame pointer chain walkers."""
from __future__ import annotations

import re
import struct
from collections.abc import Callable


# Regex patterns for stack dump parsing
RE_STACK_DUMP_ADDR = re.compile(r'^\s*>?\s*([0-9A-Fa-f]+):?\s+')
RE_HEX16 = re.compile(r'\b([0-9A-Fa-f]{16})\b')


def parse_stack_dump(lines: list[str]) -> tuple[int, bytes]:
    """Parse hex stack dump lines into a contiguous memory buffer.

    Handles both single-value lines (Dell: ``ADDR  VALUE ...``) and
    multi-value lines (EDK2: ``ADDR: V1 V2 V3 V4``).

    Returns (base_address, memory_bytes). Gaps are filled with zeros.
    """
    entries: list[tuple[int, int]] = []
    in_dump = False
    for line in lines:
        if 'stack dump' in line.lower():
            in_dump = True
            continue
        if not in_dump:
            continue
        addr_m = RE_STACK_DUMP_ADDR.match(line)
        if not addr_m:
            continue
        base_addr = int(addr_m.group(1), 16)
        rest = line[addr_m.end():]
        values = RE_HEX16.findall(rest)
        for i, val_hex in enumerate(values):
            entries.append((base_addr + i * 8, int(val_hex, 16)))

    if not entries:
        return 0, b''

    entries.sort(key=lambda x: x[0])
    base = entries[0][0]
    end = entries[-1][0] + 8
    buf = bytearray(end - base)
    for addr, val in entries:
        struct.pack_into('<Q', buf, addr - base, val)
    return base, bytes(buf)


def walk_fp_chain(
    fp: int, lr: int, stack_memory: bytes, stack_base: int,
    max_frames: int = 32,
) -> list[tuple[int, int]]:
    """Walk the ARM64 frame pointer chain through raw stack memory.

    Returns list of (return_address, frame_pointer) tuples.
    The first entry is the crash LR.
    """
    stack_end = stack_base + len(stack_memory)
    frames: list[tuple[int, int]] = []

    if lr:
        frames.append((lr, fp))

    for _ in range(max_frames):
        if fp == 0 or fp < stack_base or fp + 16 > stack_end:
            break
        off = fp - stack_base
        saved_fp = struct.unpack_from('<Q', stack_memory, off)[0]
        saved_lr = struct.unpack_from('<Q', stack_memory, off + 8)[0]
        if saved_lr == 0:
            break
        frames.append((saved_lr, saved_fp))
        fp = saved_fp

    return frames


def walk_rbp_chain(
    rbp: int, ret_addr: int, stack_memory: bytes, stack_base: int,
    max_frames: int = 32,
) -> list[tuple[int, int]]:
    """Walk the x86-64 RBP chain through raw stack memory.

    x86-64 frame layout: [RBP] = saved_RBP, [RBP+8] = return_addr.
    Returns list of (return_address, frame_pointer) tuples.
    """
    stack_end = stack_base + len(stack_memory)
    frames: list[tuple[int, int]] = []

    if ret_addr:
        frames.append((ret_addr, rbp))

    cur_rbp = rbp
    for _ in range(max_frames):
        if cur_rbp == 0 or cur_rbp < stack_base or cur_rbp + 16 > stack_end:
            break
        offset = cur_rbp - stack_base
        saved_rbp = struct.unpack_from('<Q', stack_memory, offset)[0]
        saved_ret = struct.unpack_from('<Q', stack_memory, offset + 8)[0]
        if saved_ret == 0:
            break
        frames.append((saved_ret, saved_rbp))
        if saved_rbp <= cur_rbp:
            break
        cur_rbp = saved_rbp

    return frames


def scan_stack_for_returns(
    stack_memory: bytes, stack_base: int,
    image_lo: int, image_hi: int,
    is_call_before: Callable[[int], bool] | None = None,
) -> list[int]:
    """Scan a raw stack dump for in-image return addresses.

    For every 8-byte value V in the stack where `image_lo <= V < image_hi`,
    this emits V as a candidate return address if `is_call_before(V)` is
    true (or if the callback is None, all in-range values qualify).

    This is the fallback used for Dell x86 RSODs that contain only a raw
    stack dump ("Stack trace not available") — the same trick
    processRSOD.pl uses to produce a backtrace by consulting the MSVC map.

    Returned addresses are in the order they appear on the stack (deepest
    frame first), de-duplicated consecutively to avoid padding noise.
    """
    results: list[int] = []
    last: int | None = None
    for offset in range(0, len(stack_memory) - 7, 8):
        val = struct.unpack_from('<Q', stack_memory, offset)[0]
        if val < image_lo or val >= image_hi:
            continue
        if is_call_before is not None and not is_call_before(val):
            continue
        if val == last:
            continue
        results.append(val)
        last = val
    return results
