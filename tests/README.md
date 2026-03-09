# Tests

Quokka has two test suites: **C++ unit tests** (GoogleTest) and **Python tests** (pytest).

IDA-dependent testing is done through the **Python frontend** (`test_ida_export.py`), which invokes IDA headlessly and validates the resulting `.quokka` files. This keeps IDA tests runnable without linking against IDA SDK kernel symbols.

## Prerequisites

Some test binaries are stored with [Git LFS](https://git-lfs.com/). Install `git-lfs` before cloning or running tests:

```bash
git lfs install
git lfs pull
```

Without LFS, tracked binaries will be 128-byte pointer files and tests will fail.

### Python protobuf module

Python tests import `quokka`, which requires the generated `quokka_pb2` module. Install in editable/dev mode before running pytest:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

## Directory Layout

```
tests/
  cpp/
    DataType_test.cpp   Key-snapshot iteration tests (absl::flat_hash_map)
    Util_test.cpp       scope_exit_guard, Timer, type traits, for_each_visit, UpcastVariant
    Bucket_test.cpp     SetBucket, MapBucket, MultiMapBucket, SortedView
  dataset/              Test binaries, sources, IDA databases, and pre-exported .quokka files
  python/
    tests/
      conftest.py       Root fixture (root_directory)
      offline/          Tests using pre-exported .quokka files (no IDA needed)
        conftest.py     Fixtures: prog, many_types_prog, pura_update_prog
        backends/       Disassembler backend tests (Capstone, Pypcode)
        test_ghidra_export.py  Ghidra export validation (skipped without Ghidra-exported fixtures)
      ida/              IDA integration tests (skipped when IDA unavailable)
```

## Running Tests

### C++ Tests (72 tests)

```bash
# Configure with tests enabled (Ninja recommended)
cmake -B build -DBUILD_TEST=On -G Ninja

# Build and run
cmake --build build
ctest --test-dir build

# Verbose output (shows individual gtest names)
ctest --test-dir build -V

# Run a single test suite
ctest --test-dir build -R KeySnapshotIteration
ctest --test-dir build -R ScopeExitGuard
ctest --test-dir build -R SetBucket
```

### Python Tests (48 tests)

```bash
source .venv/bin/activate
pip install -e '.[dev]'

# All tests (IDA/Ghidra tests auto-skip when unavailable)
pytest tests/python/tests/

# Offline tests only (no IDA/Ghidra needed)
pytest tests/python/tests/offline/

# IDA integration tests only
pytest tests/python/tests/ida/

# Single test by name
pytest tests/python/tests/ -k test_data_string

# Verbose output
pytest tests/python/tests/ -v
```

## C++ Tests

### Standalone (no IDA SDK required)

Always built when `-DBUILD_TEST=On`. Runs in CI on every push. All 72 tests are standalone and have no IDA SDK dependency.

| File | Test Suites (test count) | What It Tests |
|------|-----------|---------------|
| [DataType_test.cpp](cpp/DataType_test.cpp) | `KeySnapshotIteration` (3) | Regression test for iterator invalidation in `ExportCompositeDataTypes()`. Verifies that snapshotting `absl::flat_hash_map` keys before iterating allows safe insertion during the loop. |
| [Util_test.cpp](cpp/Util_test.cpp) | `ScopeExitGuard` (5), `Timer` (6), `TypeTraits` (7), `ForEachVisit` (4), `UpcastVariant` (4) | Pure-logic utilities from `Util.h` with no IDA dependency: RAII scope guard, timer arithmetic, `std::variant` type traits, visitor helpers. |
| [Bucket_test.cpp](cpp/Bucket_test.cpp) | `SetBucket` (15), `MapBucket` (9), `MultiMapBucket` (9), `SortedView` (3) | Bucket containers from `Bucket.h`: insert/emplace, deduplication, freeze/sort semantics, ref-count tracking, sorted-view iteration, error handling for post-freeze mutations. |

## Python Tests

The primary test binary is `qb-crackme` (`docs/samples/qb-crackme.quokka`, 50 functions) via the `prog` fixture. Additional fixtures `many_types_prog` and `pura_update_prog` load from `tests/dataset/` and are skipped if their `.quokka` files are missing.

### Offline Tests (`offline/`)

| File | What It Tests |
|------|---------------|
| [test_tutorial.py](python/tests/offline/test_tutorial.py) | End-to-end usage: export validation, function counting (50), CFG structure (7 blocks, 8 edges for `level0`), imported function detection (`strcmp`) |
| [test_data.py](python/tests/offline/test_data.py) | 19 tests covering: data symbols (GOT, uninitialized, string reads), c_str representations (struct, enum, pointer, array types), data cross-references, struct member access (bit offsets, dict keying by offset, `member_at`), union member access (all-offset-zero semantics, dict keying by index, `member_at`, multi-member unions like `UWeird_C`), puraUpdate regression (pre-exported) |
| [test_executable.py](python/tests/offline/test_executable.py) | Binary file reading: null-terminated string detection, sized string reads |
| [test_ghidra_export.py](python/tests/offline/test_ghidra_export.py) | 13 tests across 4 classes: Ghidra-exported `.quokka` validation -- program loading, disassembler/mode metadata, functions, segments, primitive type system, block sizes, segment ordering. Skipped when `*_ghidra.quokka` fixtures are not found. |

### IDA Export Tests (`ida/`, requires IDA Pro)

Skipped automatically when IDA is not available. These tests exercise the full export pipeline through IDA headlessly and validate results via the Python frontend.

| File | What It Tests |
|------|---------------|
| [test_ida_export.py](python/tests/ida/test_ida_export.py) | `TestPuraUpdateExport` class (8 tests): headless IDA export of puraUpdate ARM binary with 600s timeout. Validates program validity, function count (113), type and struct export, segments, ARM/32-bit architecture metadata, main function existence, multi-block CFG |
| [test_ida_apply_back.py](python/tests/ida/test_ida_apply_back.py) | `TestApplyBackFullSignature` class (4 tests): apply-back round-trip with Hex-Rays cache invalidation using sig_test binary. Verifies full signature changes (name, return type, param types, param names, param count) are reflected in both stored prototype and decompiled pseudocode |

### Backend Tests (`offline/backends/`)

| File | What It Tests |
|------|---------------|
| [test_capstone.py](python/tests/offline/backends/test_capstone.py) | Capstone disassembler: context creation for x86/x64/ARM/ARM64, instruction decoding (NOP on x86_64) |
| [test_pypcode.py](python/tests/offline/backends/test_pypcode.py) | Pypcode IR decompiler: context creation for x86/x64/ARM/ARM64, P-code operation decoding (`push rbp`). Note: `test_pypcode_decode_block` is skipped pending rewrite |

## Test Data

| File | Description |
|------|-------------|
| `qb-crackme` (24 KB, `docs/samples/`) | x86_64 binary (50 functions) with IDA database and `.quokka` file. Primary fixture (`prog`). Covers multi-block CFGs, imports, string data, xrefs, switch/jump tables. |
| `many_types_cpp` (163 KB) | | x86_64 binary with C11/C23 type stress test: bitfields, packing, alignment, typedef chains, anonymous aggregates, forward declarations, complex declarators, section placement, C++20 extension: scoped enums, templates, SIMD vectors, `__int128`, member pointers, virtual functions, atomics, ABI attributes (`clang++ -std=c++20 -g3 -O0`) |
| `many_types_cpp.quokka` (132 KB) | Pre-exported protobuf -- used by `many_types_prog` fixture |
| `puraUpdate` (22 KB) | 32-bit ARM ELF (113 functions after IDA analysis). Regression binary for `ExportCompositeDataTypes` iterator invalidation -- triggered SIGSEGV before fix |
| `puraUpdate.quokka` (75 KB) | Pre-exported protobuf -- used by `pura_update_prog` fixture |
| `sig_test` | x86_64 binary compiled from `sig_test_source.c` (`gcc -O0 -no-pie`). Contains `add_two`, `compute_three`, `use_char_ptr` with clear int/long/pointer params. Used by apply-back signature tests. |

## Frameworks and Dependencies

| Suite | Framework | Key Dependencies |
|-------|-----------|-----------------|
| C++ Standalone | GoogleTest | gtest, absl::flat_hash_map, absl::time, absl::strings |
| Python | pytest | quokka, capstone, pypcode |
| Python IDA Export | pytest | quokka, idascript, IDA Pro |
