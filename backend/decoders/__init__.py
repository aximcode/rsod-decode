"""RSOD format decoder registry.

Provides ``detect_format()`` which returns a ``FormatDecoder`` instance
for the detected RSOD format, and re-exports ``FormatDecoder`` for typing.
"""
from __future__ import annotations

from .base import FormatDecoder
from .edk2_arm64 import Edk2Arm64Decoder
from .edk2_x64 import Edk2X64Decoder
from .uefi_arm64 import UefiArm64Decoder
from .uefi_x86 import UefiX86Decoder

__all__ = ['FormatDecoder', 'detect_format']

# Detection priority: most specific first to avoid false matches.
_DECODERS: list[type[FormatDecoder]] = [
    Edk2X64Decoder,       # "!!!! X64 Exception" is unambiguous
    Edk2Arm64Decoder,     # "Synchronous Exception at 0x" + "PC 0x...(0x...+0x...)"
    UefiArm64Decoder,     # "-->PC" or "sNN ... .efi +OFFSET"
    UefiX86Decoder,       # "-->RIP" or fallback default
]


def detect_format(lines: list[str]) -> FormatDecoder:
    """Detect the RSOD format and return a decoder instance."""
    for cls in _DECODERS:
        if cls.detect(lines):
            return cls()
    return UefiX86Decoder()
