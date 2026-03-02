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
    standalone/       C++ tests with no IDA SDK dependency (always built)
  dataset/            Test binaries and exported .quokka files
  python/
    tests/            pytest test suite
      backends/       disassembler backend tests
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
| [DataType_test.cpp](cpp/standalone/DataType_test.cpp) | `KeySnapshotIteration` | Regression test for iterator invalidation in `ExportCompositeDataTypes()`. Verifies that snapshotting `absl::flat_hash_map` keys before iterating allows safe insertion during the loop. |

**Individual test cases:**

| Test | Description |
|------|-------------|
| `InsertDuringIteration` | Seeds 100 struct + 100 union entries, inserts pointer/array entries during iteration, verifies all entries present |
| `FiltersCorrectly` | Verifies the key snapshot filters by type (struct vs union) |
| `StressRehash` | 500 initial entries with 3x insertions per original, forcing multiple rehashes |

## Python Tests

All Python tests use the `qb-crackme` sample (`docs/samples/qb-crackme.quokka`) as the primary test binary via the `prog` pytest fixture.

### Core Tests

| File | What It Tests |
|------|---------------|
| [test_tutorial.py](python/tests/test_tutorial.py) | End-to-end usage: binary export verification, function counting, multi-block CFGs, imports, function types |
| [test_data.py](python/tests/test_data.py) | Data types and symbols: BaseType properties, initialized/uninitialized data, string reading, struct/union members, C string representations, cross-references, puraUpdate regression |
| [test_executable.py](python/tests/test_executable.py) | Binary file reading: null-terminated strings, sized string reads |
| [test_block.py](python/tests/test_block.py) | *(empty -- placeholder for future block tests)* |

### IDA Export Tests (requires IDA Pro)

Skipped automatically when IDA is not available. These tests exercise the full export pipeline through IDA headlessly and validate results via the Python frontend.

| File | What It Tests |
|------|---------------|
| [test_ida_export.py](python/tests/test_ida_export.py) | Headless IDA export of puraUpdate ARM binary: program validity, function count, types, structs, segments, architecture metadata, control flow |

### Backend Tests

| File | What It Tests |
|------|---------------|
| [test_capstone.py](python/tests/backends/test_capstone.py) | Capstone disassembler integration: context creation and instruction decoding for x86, x64, ARM, ARM64 |
| [test_pypcode.py](python/tests/backends/test_pypcode.py) | Pypcode IR decompiler integration: context creation and instruction decoding for x86, x64, ARM, ARM64 |

## Test Data

### Primary Sample

The `qb-crackme` binary (24 KB, ~50 functions) in `docs/samples/` with its IDA database and exported `.quokka` file. Covers multi-block control flow graphs, imports, string data, cross-references, and switch/jump tables.

### Regression Samples

| Binary | Location | Purpose |
|--------|----------|---------|
| `puraUpdate` | `tests/dataset/` | 32-bit ARM ELF (22 KB, 74 functions). Regression test for `ExportCompositeDataTypes` iterator invalidation fix -- this binary triggered a SIGSEGV before the fix. |

## Frameworks and Dependencies

| Suite | Framework | Key Dependencies |
|-------|-----------|-----------------|
| C++ Standalone | GoogleTest | gtest, absl::flat_hash_map |
| Python | pytest | quokka, capstone, pypcode |
| Python IDA Export | pytest | quokka, idascript, IDA Pro |
