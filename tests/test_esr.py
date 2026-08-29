"""Unit tests for the ARM64 ESR decode tables.

Pure table lookups — no fixtures, no backend, no LLDB.

WHY THIS EXISTS. `esr.py` had no test at all, and every name in
`EC_TABLE` from 0x2F up sat on the wrong key — by differing amounts,
so there is no off-by-N to reason with. "SError" was on 0x30 when
SError is 0x2F; the four debug-exception names were each two keys
high; and Watchpoint had no entry at all, because 0x34/0x35 were
holding Software Step's names. Every AArch64 debug exception
therefore decoded to a confidently wrong name — worse than the
"Unknown EC" printed for a value the table does not have, because a
wrong name is believed.

The values here are checked against QEMU's `target/arm/syndrome.h`,
which enumerates the architectural EC constants.
"""
from __future__ import annotations

import pytest

from rsod_decode.esr import EC_TABLE, format_esr


def _syn(ec: int, iss: int = 0) -> int:
    """Build an ESR value carrying @ec and @iss, with IL set."""
    return (ec << 26) | (1 << 25) | iss


@pytest.mark.parametrize(('ec', 'want'), [
    (0x2F, 'SError'),
    (0x30, 'Breakpoint (lower EL)'),
    (0x31, 'Breakpoint (same EL)'),
    (0x32, 'Software Step (lower EL)'),
    (0x33, 'Software Step (same EL)'),
    (0x34, 'Watchpoint (lower EL)'),
    (0x35, 'Watchpoint (same EL)'),
    (0x38, 'BKPT (AArch32)'),
])
def test_debug_exception_classes_sit_on_the_right_keys(ec: int, want: str) -> None:
    """0x2F..0x35 are SError, Breakpoint, Software Step, Watchpoint — in that
    order — and 0x38 is the AArch32 BKPT. This is the range that was wrong;
    0x38 is one of the three keys (with 0x2F and 0x31) that had no entry."""
    assert EC_TABLE[ec] == want


@pytest.mark.parametrize(('ec', 'want'), [
    (0x20, 'Instruction Abort (lower EL)'),
    (0x21, 'Instruction Abort (same EL)'),
    (0x24, 'Data Abort (lower EL)'),
    (0x25, 'Data Abort (same EL)'),
    (0x3C, 'BRK (AArch64)'),
])
def test_abort_classes_unchanged(ec: int, want: str) -> None:
    """A negative control: the abort classes, plus 0x3C above the corrected
    range, were already right and the fix must not disturb them. 0x3C is here
    deliberately -- it is the one entry above the range whose LINE the fix
    rewrote, so "untouched" is a claim about it too."""
    assert EC_TABLE[ec] == want


def test_serror_is_named_rather_than_unknown() -> None:
    """The whole point, end to end: an SError must not render as "Unknown"."""
    line = format_esr(_syn(0x2F), None)[0]
    assert 'EC=0x2F SError' in line
    assert 'Unknown' not in line


def test_breakpoint_is_not_called_serror() -> None:
    """The inverse: 0x30 must no longer claim to be an SError."""
    line = format_esr(_syn(0x30), None)[0]
    assert 'Breakpoint' in line
    assert 'SError' not in line


def test_data_abort_still_decodes_its_fault_status_code() -> None:
    """DFSC decoding hangs off the abort ECs, so it is the thing a shifted
    table would have broken silently."""
    lines = format_esr(_syn(0x25, 0x07), 0x0)
    assert 'EC=0x25 Data Abort (same EL)' in lines[0]
    assert 'Translation fault L3' in lines[1]
    assert 'NULL pointer dereference' in lines[2]
