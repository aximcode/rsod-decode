"""ARM64 ESR (Exception Syndrome Register) decode tables."""
from __future__ import annotations


EC_TABLE: dict[int, str] = {
    0x00: "Unknown", 0x01: "WFI/WFE trap", 0x07: "SVE/SIMD/FP trap",
    0x0E: "Illegal Execution State", 0x15: "SVC (AArch64)",
    0x18: "MSR/MRS trap", 0x20: "Instruction Abort (lower EL)",
    0x21: "Instruction Abort (same EL)", 0x22: "PC Alignment Fault",
    0x24: "Data Abort (lower EL)", 0x25: "Data Abort (same EL)",
    0x26: "SP Alignment Fault", 0x2C: "FP exception",
    0x30: "SError", 0x32: "Breakpoint (lower EL)",
    0x33: "Breakpoint (same EL)", 0x34: "Software Step (lower EL)",
    0x35: "Software Step (same EL)", 0x3C: "BRK (AArch64)",
}

DFSC_TABLE: dict[int, str] = {
    0x00: "Address size fault L0", 0x01: "Address size fault L1",
    0x02: "Address size fault L2", 0x03: "Address size fault L3",
    0x04: "Translation fault L0", 0x05: "Translation fault L1",
    0x06: "Translation fault L2", 0x07: "Translation fault L3",
    0x09: "Access flag fault L1", 0x0A: "Access flag fault L2",
    0x0B: "Access flag fault L3", 0x0D: "Permission fault L1",
    0x0E: "Permission fault L2", 0x0F: "Permission fault L3",
    0x10: "Synchronous external abort", 0x21: "Alignment fault",
}


def format_esr(esr: int, far: int | None) -> list[str]:
    """Decode ARM64 ESR register to human-readable lines."""
    ec = (esr >> 26) & 0x3F
    il = (esr >> 25) & 1
    iss = esr & 0x1FFFFFF
    ec_name = EC_TABLE.get(ec, f"Unknown EC 0x{ec:02X}")
    lines = [f"ESR:       0x{esr:08X} -- EC=0x{ec:02X} {ec_name}, "
             f"IL={il}, ISS=0x{iss:07X}"]
    if ec in (0x20, 0x21, 0x24, 0x25):
        dfsc = iss & 0x3F
        dfsc_name = DFSC_TABLE.get(dfsc, f"DFSC 0x{dfsc:02X}")
        lines.append(f"           {dfsc_name}")
    if far is not None:
        desc = "NULL pointer dereference" if far < 0x100 else ""
        far_line = f"FAR:       0x{far:016X}"
        if desc:
            far_line += f" -- {desc}"
        lines.append(far_line)
    return lines
