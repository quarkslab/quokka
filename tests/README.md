# Tests

Quokka has two main test suites: **C++ unit tests** (GoogleTest) for the IDA
plugin internals and **Python tests** (pytest) for the bindings and the whole
export pipeline. The Ghidra extension adds **JUnit** tests, and the Binary Ninja
extension has its own pytest suite.

IDA-dependent testing is done through the **Python frontend**: the tests run IDA
headlessly and validate the resulting `.quokka` files. This keeps IDA tests
runnable without linking against IDA SDK kernel symbols. Ghidra and Binary Ninja
integration tests follow the same approach.

## Setup

```bash
git lfs install && git lfs pull        # binaries/.quokka fixtures are in LFS (without it: pointer files, failing tests)
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'                # also generates quokka_pb2.py, required by every Python test
```

## Running

| Suite | Command | Needs |
|---|---|---|
| C++ unit tests | `cmake -B build-tests -S . -G Ninja -DNO_BUILD=On -DBUILD_TEST=On -DCMAKE_BUILD_TYPE=Debug && cmake --build build-tests && ctest --test-dir build-tests` (`-R <Suite>` filter, `-V` verbose); drop `-DNO_BUILD=On` to also build the plugin (needs an SDK option) | nothing with `NO_BUILD` (tests never link the IDA SDK) |
| Python offline | `pytest tests/python/tests/offline/` | nothing |
| IDA integration | `pytest tests/python/tests/ida/` | IDA Pro + installed plugin (`IDA_PATH` or `idat` on `$PATH`) |
| Ghidra integration | `export GHIDRA_INSTALL_DIR="$(scripts/fetch_ghidra.sh)"` (release matching the `third_party/ghidra` tag), install the extension (`ghidra_extension/README.md`), `pytest tests/python/tests/ghidra/` | Ghidra + installed extension |
| Binary Ninja integration | `pytest tests/python/tests/binja/` | Binary Ninja Python API importable |
| Ghidra extension (JUnit) | `cd ghidra_extension && ./gradlew test` | `GHIDRA_INSTALL_DIR` |
| Binary Ninja extension | `pytest binaryninja_extension/tests/` | nothing (uses a stub of the BN API) |

- `pytest tests/python/tests/` runs everything; integration suites skip automatically when their tool is missing
- IDA/Ghidra integration tests export into a temporary directory, never next to the dataset files

## Layout

| Path | Content |
|---|---|
| `cpp/` | GoogleTest: `Bucket_test` (dedup containers), `Util_test` (scope guard, timer, variant helpers), `DataType_test` (iterator-invalidation regression) |
| `python/tests/offline/` | tests on pre-exported `.quokka` files: tutorial, data/types, type-to-type xrefs, edits (`add_type`, apply types, commit/regenerate), CLI output templates, Ghidra install detection, IDA/Ghidra/Binary Ninja export loading; `backends/` = Capstone + Pypcode |
| `python/tests/ida/` | headless IDA export (many_types_cpp, puraUpdate, deferred decompiler types, hidden segments), apply-back, commit/regenerate |
| `python/tests/ghidra/` | headless Ghidra export, CLI, apply-back |
| `python/tests/binja/` | real Binary Ninja export (LIGHT, SELF_CONTAINED, load round-trip) |
| `dataset/` | test binaries, sources, pre-exported fixtures (below); local IDA databases (`.i64`, gitignored) are opened instead of the binary when present |

## Fixtures

| File | Used by | Notes |
|---|---|---|
| `docs/samples/qb-crackme(.quokka)` | `prog` (offline), `qb_crackme` (binja), Ghidra CLI | x86-64 crackme; primary fixture (multi-block CFGs, imports, strings, xrefs, jump tables) |
| `many_types_cpp`, `many_types_cpp.quokka`, `many_types_cpp_ghidra.quokka` | `many_types_prog`, Ghidra fixtures, IDA export | type stress test built from `many_types.cpp` (`clang++ -std=c++20 -g3 -O0`): bitfields, packing, typedef chains, anonymous aggregates, templates, SIMD, `__int128`, virtual functions; `many_types.c` is the C variant |
| `puraUpdate`, `puraUpdate.quokka`, `puraUpdate_ghidra.quokka` | `pura_update_prog`, Ghidra fixtures, IDA export | 32-bit ARM ELF; regression for an iterator invalidation in `ExportCompositeDataTypes` |
| `qb-crackme_binja.quokka` | `offline/test_binja_export.py` | regenerate: `python binaryninja_extension/export_headless.py docs/samples/qb-crackme -o tests/dataset/qb-crackme_binja.quokka` |
| `sig_test` (`sig_test_source.c`, `gcc -O0 -no-pie`) | IDA/Ghidra apply-back, commit/regenerate | `add_two`, `compute_three`, `use_char_ptr` with simple int/long/pointer params |
| `nf_nat_pt.ko` | IDA deferred type export | decompilation promotes `inport` to `_WORD[300]` |
| `StatusCodeHandlerPei.efi` | IDA hidden segments | `.reloc` segment regression (#115) |

`prog` is required; the other offline fixtures skip when their `.quokka` file is missing. Tests assert structural properties rather than exact counts where disassembler analysis may change.

## CI (`.github/workflows/`)

| Workflow | Runs | On |
|---|---|---|
| `build.yml` | C++ build matrix + `ctest`; Ghidra integration on full builds (every 30 commits or tag) | push to main, PRs (path-filtered), tags |
| `python.yml` | `pytest tests/python` on a Python/OS matrix | push to main, PRs (path-filtered) |
| `ghidra.yml` | extension build + install, Ghidra apply-back tests; tags upload the zip | push to main, PRs (path-filtered), tags |
| `binaryninja.yml` | `quokka_pb2.py` freshness guard + `binaryninja_extension/tests/` | push to main, PRs (path-filtered) |
| `doc.yml` | MkDocs deployment | push to main (path-filtered) |
| `release.yml` | PyPI publishing | GitHub release published |
| `zizmor.yml` | GitHub Actions security scan | push to main, PRs touching workflows |
