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

## Directory Layout

```
tests/
  cpp/
    DataType_test.cpp   C++ unit tests (no IDA SDK dependency, always built)
  dataset/              Test binaries, sources, IDA databases, and pre-exported .quokka files
  python/
    tests/
      conftest.py       Root fixture (root_directory)
      offline/          Tests using pre-exported .quokka files (no IDA needed)
        conftest.py     Fixtures: prog, many_types_prog, pura_update_prog
        backends/       Disassembler backend tests (Capstone, Pypcode)
      ida/              IDA integration tests (skipped when IDA unavailable)
```

## Running Tests

### C++ Tests

```bash
# Configure with tests enabled
cmake -B build -DBUILD_TEST=On

# Build and run
cmake --build build
ctest --test-dir build
```

### Python Tests

```bash
pip install -e '.[dev]'
pytest tests/python/tests/
```

## C++ Tests

### Standalone (no IDA SDK required)

Always built when `-DBUILD_TEST=On`. Runs in CI on every push.

| File | Test Suite | What It Tests |
|------|-----------|---------------|
| [DataType_test.cpp](cpp/DataType_test.cpp) | `KeySnapshotIteration` | Regression test for iterator invalidation in `ExportCompositeDataTypes()`. Verifies that snapshotting `absl::flat_hash_map` keys before iterating allows safe insertion during the loop. |

**Individual test cases:**

| Test | Description |
|------|-------------|
| `InsertDuringIteration` | Seeds 100 struct + 100 union entries, inserts pointer/array entries during iteration, verifies all entries present |
| `FiltersCorrectly` | Verifies the key snapshot filters by type (struct vs union) |
| `StressRehash` | 500 initial entries with 3x insertions per original, forcing multiple rehashes |

## Python Tests

The primary test binary is `qb-crackme` (`docs/samples/qb-crackme.quokka`, 50 functions) via the `prog` fixture. Additional fixtures `many_types_prog` and `pura_update_prog` load from `tests/dataset/` and are skipped if their `.quokka` files are missing.

### Offline Tests (`offline/`)

| File | What It Tests |
|------|---------------|
| [test_tutorial.py](python/tests/offline/test_tutorial.py) | End-to-end usage: export validation, function counting (50), CFG structure (7 blocks, 8 edges for `level0`), imported function detection (`strcmp`) |
| [test_data.py](python/tests/offline/test_data.py) | 19 tests covering: data symbols (GOT, uninitialized, string reads), c_str representations (struct, enum, pointer, array types), data cross-references, struct member access (bit offsets, dict keying by offset, `member_at`), union member access (all-offset-zero semantics, dict keying by index, `member_at`, multi-member unions like `UWeird_C`), puraUpdate regression (pre-exported) |
| [test_executable.py](python/tests/offline/test_executable.py) | Binary file reading: null-terminated string detection, sized string reads |

### IDA Export Tests (`ida/`, requires IDA Pro)

Skipped automatically when IDA is not available. These tests exercise the full export pipeline through IDA headlessly and validate results via the Python frontend.

| File | What It Tests |
|------|---------------|
| [test_ida_export.py](python/tests/ida/test_ida_export.py) | `TestPuraUpdateExport` class (8 tests): headless IDA export of puraUpdate ARM binary with 600s timeout. Validates program validity, function count (113), type and struct export, segments, ARM/32-bit architecture metadata, main function existence, multi-block CFG |

### Backend Tests (`offline/backends/`)

| File | What It Tests |
|------|---------------|
| [test_capstone.py](python/tests/offline/backends/test_capstone.py) | Capstone disassembler: context creation for x86/x64/ARM/ARM64, instruction decoding (NOP on x86_64) |
| [test_pypcode.py](python/tests/offline/backends/test_pypcode.py) | Pypcode IR decompiler: context creation for x86/x64/ARM/ARM64, P-code operation decoding (`push rbp`). Note: `test_pypcode_decode_block` is skipped pending rewrite |

## Test Data

### Primary Sample

The `qb-crackme` binary (24 KB, 50 functions) in `docs/samples/` with its IDA database and exported `.quokka` file. Covers multi-block control flow graphs, imports, string data, cross-references, and switch/jump tables.

### Dataset (`tests/dataset/`)

| File | Description |
|------|-------------|
| `many_types_cpp` (163 KB) | x86_64 binary with C11/C23 type stress
test: bitfields, packing, alignment, typedef chains, anonymous
aggregates, forward declarations, complex declarators, section
placement, C++20 extension: scoped enums, templates, SIMD vectors, `__int128`, member pointers, virtual functions, atomics, ABI
attributes (`clang++ -std=c++20 -g3 -O0`) |
| `many_types_cpp.quokka` (132 KB) | Pre-exported protobuf -- used by `many_types_prog` fixture |
| `puraUpdate` (22 KB) | 32-bit ARM ELF (113 functions after IDA analysis). Regression binary for `ExportCompositeDataTypes` iterator invalidation -- triggered SIGSEGV before fix |
| `puraUpdate.quokka` (75 KB) | Pre-exported protobuf -- used by `pura_update_prog` fixture |

## Frameworks and Dependencies

| Suite | Framework | Key Dependencies |
|-------|-----------|-----------------|
| C++ Standalone | GoogleTest | gtest, absl::flat_hash_map |
| Python | pytest | quokka, capstone, pypcode |
| Python IDA Export | pytest | quokka, idascript, IDA Pro |
