from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from rsod_decode.decoder import AnalysisResult
from rsod_decode.models import SymbolSource


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SYMBOL_ROOT = Path(
    os.environ.get(
        "RSOD_TEST_SYMBOL_ROOT",
        Path.home() / "projects/aximcode/uefi-devkit/build/crashhandler",
    )
)

# Sibling source-tree for axl-sdk, used by the CrashTest ELF fixtures
# whose DWARF points at `src/crt0/axl-crt0-native.c` etc. — paths that
# live outside the rsod-decode checkout. Tests that assert source
# files for those frames pass this via `--source-path` / `source_paths=`.
AXL_SDK_ROOT = Path(
    os.environ.get(
        "RSOD_TEST_AXL_SDK_ROOT",
        Path.home() / "projects/aximcode/axl-sdk",
    )
)


@dataclass(frozen=True)
class DatasetSpec:
    key: str
    rsod_file: str
    symbol_path: Path
    expected_format: str
    # Physical frame count — what the parser / FP-chain walker
    # produces from the raw stack dump alone. Asserted by tests
    # that exercise `analyze_rsod` directly.
    expected_frames: int
    expected_resolved: int
    expected_modules: int
    expected_vregs: int
    expected_stack_size: int
    expected_lbr: int
    expected_image_base: int | None = None
    companion_path: Path | None = None
    pdb_path: Path | None = None
    base_override: int | None = None
    # Out-of-tree source roots that should be appended to the
    # `--source-path` search list so DWARF paths like
    # `src/crt0/axl-crt0-native.c` (referenced from CrashTest.so but
    # living in the sibling axl-sdk checkout) actually resolve. Tuple
    # instead of list so the dataclass stays hashable.
    source_roots: tuple[Path, ...] = ()
    # Frame count after the app-layer tail-call reconstructor runs.
    # Defaults to `expected_frames` when no reconstruction applies;
    # fixtures with MSVC tail-call elision (currently just
    # psa_x64_forcecrash) set this to the reconstructed total.
    # Asserted by API-level tests via conftest.create_api_session.
    expected_api_frames: int | None = None


@dataclass
class DatasetRun:
    spec: DatasetSpec
    rsod_text: str
    source: SymbolSource
    result: AnalysisResult


DATASET_SPECS: dict[str, DatasetSpec] = {
    "edk2_aa64": DatasetSpec(
        key="edk2_aa64",
        rsod_file="rsod_qemu_devkit.txt",
        symbol_path=SYMBOL_ROOT / "aa64" / "CrashTest.so",
        expected_format="edk2_arm64",
        expected_frames=17,
        expected_resolved=9,
        expected_modules=5,
        expected_vregs=32,
        expected_stack_size=512,
        expected_lbr=0,
        source_roots=(AXL_SDK_ROOT,),
    ),
    "dell_aa64": DatasetSpec(
        key="dell_aa64",
        rsod_file="rsod_dell_aa64.txt",
        symbol_path=SYMBOL_ROOT / "aa64" / "CrashTest.so",
        expected_format="uefi_arm64",
        expected_frames=25,
        expected_resolved=8,
        expected_modules=324,
        expected_vregs=32,
        expected_stack_size=4096,
        expected_lbr=0,
        expected_image_base=0x782B122000,
        source_roots=(AXL_SDK_ROOT,),
    ),
    "dell_x64": DatasetSpec(
        key="dell_x64",
        rsod_file="rsod_dell_x64.txt",
        symbol_path=SYMBOL_ROOT / "x64" / "CrashTest.so",
        expected_format="uefi_x86",
        expected_frames=6,
        expected_resolved=1,
        expected_modules=316,
        expected_vregs=0,
        expected_stack_size=4096,
        expected_lbr=2,
        source_roots=(AXL_SDK_ROOT,),
    ),
    # Real Dell EPSA x86-64 crash: PE (.efi) + MSVC .map. Exercises the
    # full MAP+PE path: symbols from .map, disassembly from .efi via
    # PEBinary, and stack-dump return-address reconstruction because the
    # RSOD text says "Stack trace not available". Frames 1-13 are real
    # EPSA C++ functions resolved by walking the raw stack dump through
    # capstone call-site verification.
    "psa_x64": DatasetSpec(
        key="psa_x64",
        rsod_file="psa/rsod_psa_x64.txt",
        symbol_path=FIXTURES_DIR / "psa" / "psa_x64.map",
        companion_path=FIXTURES_DIR / "psa" / "psa_x64.efi",
        expected_format="uefi_x86",
        expected_frames=14,
        expected_resolved=0,
        expected_modules=299,
        expected_vregs=0,
        expected_stack_size=4096,
        expected_lbr=0,
    ),
    # Deterministic EPSA crash from the -forcecrash hook (see
    # tests/fixtures/psa_x64_forcecrash/BUILD.md for the build procedure
    # and ground-truth value table). Same MAP+PE load path as psa_x64
    # but with known call chain and known struct values so the
    # corresponding ground-truth test can make strict assertions. No
    # base_override — this build is not relocated at load time
    # (image_base == preferred_base == 0x180000000).
    "psa_x64_forcecrash": DatasetSpec(
        key="psa_x64_forcecrash",
        rsod_file="psa_x64_forcecrash/rsod_psa_x64.txt",
        symbol_path=FIXTURES_DIR / "psa_x64_forcecrash" / "psa_x64.map",
        companion_path=FIXTURES_DIR / "psa_x64_forcecrash" / "psa_x64.efi",
        pdb_path=FIXTURES_DIR / "psa_x64_forcecrash" / "psa_x64.pdb",
        expected_format="uefi_x86",
        expected_frames=4,
        # 4 physical frames + 1 synthetic `run_crashtest` inserted by
        # the tail-call reconstructor once the LLDB backend lands.
        expected_api_frames=5,
        expected_resolved=1,
        expected_modules=316,
        expected_vregs=0,
        expected_stack_size=4096,
        expected_lbr=2,
        expected_image_base=0x180000000,
    ),
}
