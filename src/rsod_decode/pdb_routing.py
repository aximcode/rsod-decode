"""PE/.map/.pdb companion-file detection helpers.

Shared between the Flask server (app.py), the CLI (decoder.py), and the
web launcher (server.py). Lives in its own module so the CLI import path
doesn't drag Flask in through app.py.
"""
from __future__ import annotations

from pathlib import Path

from .symbols import is_pe


def _pair_map_with_pe(
    primary: Path, extras: list[Path],
) -> tuple[Path | None, list[Path]]:
    """Return (companion, filtered_extras) if primary has a paired PE/.map
    companion in extras, else (None, extras) unchanged.

    MSVC EPSA commonly names the map file `psa.efi.map`, so we also match
    by full-name suffix in addition to stem equality.
    """
    prim_name = primary.name.lower()
    prim_stem = primary.stem.lower()
    prim_is_pe = is_pe(primary)
    prim_is_map = prim_name.endswith('.map')
    if not (prim_is_pe or prim_is_map):
        return None, extras

    for i, ex in enumerate(extras):
        ex_name = ex.name.lower()
        ex_stem = ex.stem.lower()
        ex_is_pe = is_pe(ex)
        ex_is_map = ex_name.endswith('.map')
        same_stem = ex_stem == prim_stem
        map_for_pe = ex_name == f"{prim_name}.map"  # psa.efi + psa.efi.map
        pe_for_map = prim_name == f"{ex_name}.map"  # psa.efi.map + psa.efi
        if prim_is_pe and ex_is_map and (same_stem or map_for_pe):
            return ex, extras[:i] + extras[i + 1:]
        if prim_is_map and ex_is_pe and (same_stem or pe_for_map):
            return ex, extras[:i] + extras[i + 1:]
    return None, extras


def _pop_pdb_for(stem: str, extras: list[Path]) -> tuple[Path | None, list[Path]]:
    """Pull a `<stem>.pdb` out of extras if one is present.

    Returned (pdb, remaining). Stem match is case-insensitive, and we
    strip one trailing extension from each candidate so `psa.efi.pdb`
    pairs with `psa.efi` as well as `psa.pdb` pairing with `psa`.
    """
    stem_l = stem.lower()
    for i, ex in enumerate(extras):
        if ex.name.lower().endswith('.pdb') and \
                ex.stem.lower() == stem_l:
            return ex, extras[:i] + extras[i + 1:]
    return None, extras
