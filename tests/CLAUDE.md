# Tests -- `tests/`

Commands, layout, fixtures, CI: `tests/README.md`. Rules for agents:

- C++ tests: reuse the existing `build-debug/` when configured with `-DBUILD_TEST=On` (never reconfigure from scratch, `src/CLAUDE.md`); without an SDK use `-DNO_BUILD=On` as in `tests/README.md`
- Every fix or feature adds a regression test; exporter changes also need the IDA/Ghidra integration suites
- Integration tests export into `tmp_path`; never export next to `tests/dataset/` files (stale IDA databases, see `src/CLAUDE.md` pitfalls)
- Refresh a pre-exported fixture when exporter output changes: re-export from a clean temp folder, replace the file in `tests/dataset/` (LFS)
- Assert structural properties (ranges, presence) for disassembler-dependent values, not exact counts
- New dataset binaries: LFS-track them in `.gitattributes`, ship the source (or provenance) and a test that uses them; never commit third-party binaries
