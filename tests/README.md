# Tests

Quokka has two test suites: **C++ unit tests** (GoogleTest) and **Python tests** (pytest).

## Directory Layout

```
tests/
  cpp/
    standalone/       C++ tests with no IDA SDK dependency (always built)
    ida/              C++ tests requiring IDA SDK runtime (optional)
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

To also build IDA-dependent tests (requires IDA SDK at runtime):

```bash
cmake -B build -DBUILD_TEST=On -DBUILD_IDA_TESTS=On
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

### IDA-Dependent (requires IDA SDK runtime)

Built only with `-DBUILD_IDA_TESTS=On`. Not currently run in CI (IDA kernel symbols unavailable outside the plugin runtime).

| File | Status | What It Tests |
|------|--------|---------------|
| [Quokka_test.cpp](cpp/ida/Quokka_test.cpp) | Active | Test harness -- initializes GoogleTest and the Quokka logger |
| [Bucket_test.cpp](cpp/ida/Bucket_test.cpp) | Active | `BucketNew<Element>` deduplication container: add, delete, frequency histogram |
| [Block_test.cpp](cpp/ida/Block_test.cpp) | Commented out | Block resizing, fake block handling, address boundary validation (`IsBetween`) |
| [Proto_test.cpp](cpp/ida/Proto_test.cpp) | Disabled | Protobuf `MessageDifferencer` sketch for comparing generated vs expected `.quokka` files |

## Python Tests

All Python tests use the `qb-crackme` sample (`docs/samples/qb-crackme.quokka`) as the primary test binary via the `prog` pytest fixture.

### Core Tests

| File | What It Tests |
|------|---------------|
| [test_tutorial.py](python/tests/test_tutorial.py) | End-to-end usage: binary export verification, function counting, multi-block CFGs, imports, function types |
| [test_data.py](python/tests/test_data.py) | Data types and symbols: BaseType properties, initialized/uninitialized data, string reading, struct/union members, C string representations, cross-references |
| [test_executable.py](python/tests/test_executable.py) | Binary file reading: null-terminated strings, sized string reads |
| [test_block.py](python/tests/test_block.py) | *(empty -- placeholder for future block tests)* |

### Backend Tests

| File | What It Tests |
|------|---------------|
| [test_capstone.py](python/tests/backends/test_capstone.py) | Capstone disassembler integration: context creation and instruction decoding for x86, x64, ARM, ARM64 |
| [test_pypcode.py](python/tests/backends/test_pypcode.py) | Pypcode IR decompiler integration: context creation and instruction decoding for x86, x64, ARM, ARM64 |

## Test Data

### Primary Sample

The `qb-crackme` binary (24 KB, ~50 functions) in `docs/samples/` with its IDA database and exported `.quokka` file. Covers multi-block control flow graphs, imports, string data, cross-references, and switch/jump tables.

## Frameworks and Dependencies

| Suite | Framework | Key Dependencies |
|-------|-----------|-----------------|
| C++ Standalone | GoogleTest | gtest, absl::flat_hash_map |
| C++ IDA | GoogleTest | gtest, ida64, quokka_shared, protobuf |
| Python | pytest | quokka, capstone, pypcode |
