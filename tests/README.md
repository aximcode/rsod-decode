RSOD Regression Test Suite

Fixtures
- tests/fixtures/rsod_qemu_devkit.txt
- tests/fixtures/rsod_dell_aa64.txt
- tests/fixtures/rsod_dell_x64.txt

External symbol binaries (tests skip cleanly if missing)
- AA64: $RSOD_TEST_SYMBOL_ROOT/aa64/CrashTest.so
- X64:  $RSOD_TEST_SYMBOL_ROOT/x64/CrashTest.so

RSOD_TEST_SYMBOL_ROOT defaults to:
  ~/projects/aximcode/uefi-devkit/build/crashhandler

Set it to point at your own crashhandler build tree, or leave unset and let
tests skip if the binaries aren't present.

Run
- pytest -m parser
- pytest -m api
- pytest -m "api and gdb"
- pytest
- RSOD_TEST_SYMBOL_ROOT=/path/to/build/crashhandler pytest
