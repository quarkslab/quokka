# Roadmap

`Quokka` is not perfect and some features could be improved. This page tracks what is done, what is
planned for the 1.0.0 release, and what comes later.

Do not hesitate to open Issues for requesting features.

- **P/E/I**: Priority / Effort / Impact (H = High, M = Medium, L = Low, XH = Extremely High).
- **Status**: [V] verified in the code -- [C] reported done, not re-verified -- [B] implemented but not merged.
- File and line references are as of 2026-09-28.

---

## 1. Done

| Id | Item | Status |
|---|---|---|
| D-1 | Ghidra extension (>= 12.0.3, see [Installation](installation.md#ghidra-extension)), LIGHT mode: exporter pipeline, Gradle wrapper, version generated from `build.gradle`, consistent install path + GUI-installed extensions, README, CLI / `Program.generate` for Ghidra, auto-fetch of the Ghidra release matching the submodule tag | [V] |
| D-2 | Typedef support end-to-end (proto 1.0.0, IDA, Ghidra, Python, tests, docs) | [V] |
| D-3 | Type-to-type cross-references (IDA, Ghidra, Python, docs, tests) -- `0ebcb7f` | [V] |
| D-4 | `Program.add_type()` (a `c_str: str` or a `Type` object; both store the C string; new user-defined types flagged `is_new`); `Program.write()` (writes the protobuf back, preserving everything except new additions like `is_new` types); `override=True` no longer overwrites the `.i64` | [V] |
| D-5 | Ghidra per-type `c_str` via `CTypeRenderer` + valid C headers | [V] |
| D-6 | Decompiler cache invalidation on IDA apply-back -- `9aa729c` | [V] |
| D-7 | Types information: structures, enumerations, unions, arrays, pointers (see [Types](types.md)) | [V] |
| D-8 | Decompiler: optional Hex-Rays pseudocode export (see [Decompilation](decompilation.md)) | [V] |
| D-9 | LZMA compression (upstream PR #88) rebased, merged, and ported: IDA (`include/quokka/LzmaStreambuf.h`), Ghidra (`ExportPipeline.java`, XZ), BinaryNinja (`export.py`, optional); Python loader reads compressed and raw files | [V] (see R-TEST-1, L-EXP-9) |
| D-10 | CI hardening: Windows removed from upload matrix, C++ tests on PRs, Ghidra tests no longer duplicated (but JUnit now never runs, R-TEST-4), path filters, concurrency controls, Ghidra download cache, Python version/OS matrix, warm-cache overhead; `fail-fast: false` | [C]; fail-fast [V] `python.yml:37` |
| D-11 | Docs review; CLI review + tests; CLI `-o` output template + multiple inputs | [C] |
| D-12 | `Data.prev` / `Data.next`; deferred type export (decompiler-created types captured) | [V] |
| D-13 | v1 exporter internals: CompositeType without RefCounter; merged `next_chunk_addr`/`next_func_chunk`; FuncChunk refactor; references by basic-block instruction index; segment permissions in protobuf; data/datatype order (incl. enums); `cube_mgmt` xref fix; IDA SDK matrix trimmed to latest per major + latest two (release matrix); abseil/protobuf cached in CI | [C] |
| D-14 | BinaryNinja extension (UI + headless, protobuf freshness CI guard, docs, tests, SELF_CONTAINED export) -- PR #112 (2026-06-28) | [V] |
| D-16 | Ghidra SELF_CONTAINED export (instructions, mnemonics, operands) and optional decompilation (`DecompInterface` -> `Function.decompiled_code`; GUI option, `--decompiled`) -- added by PR #120 (`a54bf7e`) | [V] code; no Python test yet (R-TEST-2) |
| D-15 | Ghidra apply-back: `Program.commit()` for Ghidra via `_commit_edits_ghidra`, unified `disassembler_path`, tested in CI -- PR #120 (was rated P/E/I M/H/H, largest open task) | [V] |

---

## 2. Release 1.0.0 -- proposed scope

Rule: 1.0.0 freezes the Python API and the protobuf schema. Breaking changes land now or wait for 2.0.

### 2a. Integration

- **R-GIT-1** Synced with upstream `main` on 2026-09-28 (`6ac3e74`): #112 BinaryNinja, #118 Hex-Rays plugin packaging, #120 Ghidra apply-back, #129 Ghidra xref attachments, #132 protobuf 7.35, #133 IDA 9.3 inport test, #134 hidden segments (fixes #115). Still open upstream: #122 (R-CI-2), dependabot #136, #139.
- **R-GIT-2** Function load/unload + context manager (`with func:`), reference-counted, so memory can be reclaimed on binaries with thousands of functions (lazily created blocks are never freed today) -- [B] implemented in an unpublished prototype (2026-03-12), not merged, conflicts with current `main`. Breaking: 1.0.0 or never. State of the prototype:
    - Implemented as designed: `_load_count`, `is_loaded`, `load()`/`unload()`, `__enter__`/`__exit__`, `FunctionNotLoadedError` (exported), guards on `__getitem__`/`values`/`items`/`blocks`/`instructions`/`strings`/`constants`/`get_instruction`, `end`/`size` from chunk metadata, invalidation of `strings`/`constants`/`instructions` on unload, IDA apply-back wrapped in `with function:`, docs + tutorials updated, 44 new tests (offline suite: 209 passed on the prototype).
    - Deviation from the design: `Program.get_instruction()` became a context manager that auto-loads the function (design: raise `FunctionNotLoadedError`). Plain calls now return a context-manager object instead of an `Instruction`, and the yielded instruction is detached after exit. Decide.
    - Gaps: see R-PY-11 (dict protocol); callers added to `main` after March (`get_item`, `call_target`, BinaryNinja, Ghidra apply-back #120) not audited; `add_edge` implicitly requires a loaded function; `unload()` on an unloaded function is a silent no-op.

### 2b. API decisions before the freeze

- **R-API-1** (To decide) `Program.flush()` to persist in-memory edits to the `.quokka` file: explicit only, or auto-invoked when edits are applied? Relation to `Program.write()` (P/E/I H/M/H).
- **R-API-2** `data_refs_to` returns `Data | Function | Address` and forces `isinstance` checks. Keep the mixed return, or return addresses only and resolve with `Program.get_item(addr)`?
- **R-API-3** Forward xrefs from/to the first instruction onto the owning `Function`; forward instruction xrefs to the `Function` object (P/E/I L/M/M). Decide now, implement possibly later.
- **R-API-4** Untyped data with a known size (e.g. 1 or 4 from IDA): automatically apply a `BaseType`?
- **R-API-5** Default of `regenerate(overwrite=...)` -- should it be `False` (current)?
- **R-API-6** Remove Python enums that shadow protobuf enums.
- **R-API-7** Remove `FunctionType.LIBRARY` (P/E/I L/L/L).
- **R-API-8** Operand protobuf fields: merge `value` with `address`; `other` as umbrella value (`proto/quokka.proto:117,119`). Schema change: now or 2.0.
- **R-API-9** `DATA_INDIR` references are treated as reads -- distinguish read/write? (`data.py:183`, `instruction.py:456`).
- **R-API-10** Supported IDA SDK floor: `README.md:70` and `ida-plugin.json` (`idaVersions` 9.1-9.3) say IDA 9.1+, the installation guide describes >= 9.2 as "the new way", but the CI FULL matrix still builds 7.4-9.1 and the LIGHT matrix is "temporarily set to 9.x" (`build.yml:51-54`); `src/api_v8/` is still present. Decide and align code, CI and docs (relates to L-IDA-1).
- **R-API-11** Align on the caching design choice (issue #28).

### 2c. API fixes and additions

- **R-PY-1** Fix unsorted iteration of `Data`, basic blocks, and similar collections. Canonical order: address, then index; apply consistently (P/E/I H/L-M/H).
- **R-PY-2** Make `Program.get_item` comply with its docstring, or update docstring + behavior to an agreed contract (P/E/I H/L/M-H). Currently returns `Function | Instruction`.
- **R-PY-3** `Instruction.call_target` returning an address, or `None` if not applicable; both direct calls and indirect/tail-calls (P/E/I H/L-M/H). Currently returns a `Function`.
- **R-PY-4** `Instruction.prev` / `Instruction.next`, ONLY at block level (P/E/I H/L-M/H).
- **R-PY-5** `Function.first_instruction` -- Python frontend only, no protobuf change (P/E/I L/L/L).
- **R-PY-6** Retrieve the calling convention for functions: the protobuf field exists, `Function.__init__()` does not read it; wire it to a `Function.calling_convention` property (P/E/I H/M/H; `function.py:148`).
- **R-PY-7** Bug: `instruction.py:653` reads `operand_strings`, which no longer exists.
- **R-PY-9** BinaryNinja in the Python orchestration: `Program.from_binary`, backend auto-detection and `quokka-cli` have no BinaryNinja path. Decide 1.0.0 or later.
- **R-PY-10** `Program.get_function` approximate name lookup is a plain substring match (`program.py:711`). Decide the semantics before the freeze.
- **R-PY-12** `Program.write()` writes an uncompressed protobuf while all exporters write LZMA; decide the contract (loader accepts both).
- **R-PY-13** Stale docstrings: `from_binary` says the default timeout is 10 min (actual 0); `commit` says `database_file` is required for IDA (defaults to `<exec>.i64`).
- **R-PY-14** Python drops `decompiled=True` for Ghidra exports with a "not supported yet" warning (`program.py`), but the extension's headless script accepts `--decompiled` since PR #120: wire it through.
- **R-PY-15** Bug: IDA export passes `-OQuokkaMode:FULL` (`ExporterMode.name`), which the plugin does not recognize: `quokka-cli -m full` with IDA silently produces LIGHT. Passing `SELF_CONTAINED` instead would hit the unimplemented IDA path (L-EXP-1): fix together.
- **R-PY-11** Bug: `Function` is a `dict` subclass whose content depends on loading, but `__contains__`, `__iter__`, `get` and `__eq__` are not overridden. On a function whose blocks are not loaded: `addr in func` is `False`, iteration is empty and `get()` returns `None` while `len()` is non-zero; any two such functions compare equal. Reproduced on `main` and on the R-GIT-2 prototype.

### 2c'. Exporter fixes

- **R-EXP-1** Bug: IDA registers the IDC function as `"quokka"` but unregisters `"Quokka"` (`src/Quokka.cpp:280,390` vs `:475`).
- **R-EXP-2** Hash contract: IDA writes MD5 when available and SHA-256 only as fallback (`src/FileMetadata.cpp:134-146`); schema docs promised SHA-256. Pick one contract across exporters.
- **R-EXP-3** Ghidra type order is not sorted (`TypeExporter` follows `getAllDataTypes()` order): determinism relies on Ghidra iteration order. Sort or prove stable.
- **R-EXP-5** Ghidra headless `--mode=` silently falls back to LIGHT on unknown values (`QuokkaExportHeadless.java`), against the extension's no-silent-fallback rule; same for the IDA plugin (`-OQuokkaMode`).
- **R-EXP-4** Stale doc comment: `ExportBinary()` promises a `/tmp` fallback that does not exist (`src/Quokka.cpp:136`); Ghidra `Compat.requireMinimumVersion()` is never called.

### 2d. Tests, CI, release

- **R-TEST-4** Ghidra JUnit tests never run in CI: workflows only call `./gradlew installExtension` (depends on `buildExtension`, not `test`); the step name "Build, test, and install" is misleading.
- **R-TEST-2** No Python test covers Ghidra SELF_CONTAINED or decompiled exports (D-16), nor `tests/python/tests/binja/` in CI.
- **R-TEST-1** The committed IDA/Ghidra `.quokka` fixtures predate LZMA (raw protobuf, refreshed 2026-03-11): offline tests never load a compressed IDA/Ghidra export. Refresh the fixtures or add a compressed fixture.
- **R-CI-1** Refine the full-matrix CI build: it currently runs every 30 commits or on tag pushes, not on a schedule; the FULL matrix contents must follow R-API-10.
- **R-CI-2** Support the Debian stable glibc version (issue #51, PR #122).
- **R-REL-1** Binary release plan (issue #113).
- **R-CI-3** `ci/build.dockerfile` / `ci/publish.dockerfile` are unused by any workflow since 2024 and lack liblzma; remove or revive (relates to R-CI-2, `docs/contributing.md` IDA image section).

### 2e. Docs

- **R-DOC-1** Documentation gaps: `prog.data` is not documented; property types are missing throughout the API reference -- audit and fill (P/E/I L/M/M).
- **R-DOC-2** Mode docs consistency -- fixed 2026-09-28 (FULL: Ghidra + Binary Ninja; IDA LIGHT only). Re-check when IDA gains FULL.
- **R-DOC-6** `docs/features.md` backend table has no Binary Ninja column; verify each feature and add it.
- **R-TEST-3** `tests/dataset/qb-crackme_binja.quokka` is committed outside LFS, unlike the other `.quokka` fixtures.
- **R-DOC-3** v0 -> v1 migration notes / changelog: protobuf changes (backend meta, segment-relative addressing, composite/enum types, no chunks, block edges, operand model, comment locations, reference model), plus load/unload if merged.

---

## 3. Later

### Exporters -- common

- **L-EXP-1** FULL / SELF_CONTAINED mode (P/E/I M/XH/H). IDA: `src/Writer.cpp:331` asserts "Not implemented yet", `src/Function.cpp:306`. Ghidra: implemented (D-16). BinaryNinja: implemented (`exporters/instructions.py`) and covered by a real-BinaryNinja integration test in `tests/python/tests/binja/`.
- **L-EXP-2** Write protobuf objects on the fly without hoarding them (possible for some, like meta and functions); Ghidra memory use on large binaries.
- **L-EXP-3** Split the protobuf `Quokka` message into several smaller messages to avoid the 2 GB limit.
- **L-EXP-4** Sort data types/enums by frequency.
- **L-EXP-5** Xrefs to functions without instructions (e.g. imported functions); unknown data with xref -- to be checked (P/E/I L/M/L).
- **L-EXP-6** Export function types (typedefs to function pointers currently resolve to a pointer or `TYPE_UNK`); let members reference typedefs instead of resolved types.
- **L-EXP-7** Stack variables: IDA defines stack variables in the function; exporting them could be valuable for some workflows.
- **L-EXP-8** Operands data: operands are exported but hard to understand outside the disassembler without its documentation; exporting information on them could be interesting.
- **L-EXP-9** No option to disable compression in the IDA and Ghidra exporters (BinaryNinja has `--no-compress`).
- **L-EXP-10** [Fat binaries](https://en.wikipedia.org/wiki/Fat_binary): IDA disassembles them but Quokka only exports the first one; allow selecting which one to export.
- **L-EXP-11** Verify the support for unknown architectures: Quokka should export any binary but has barely been tested on other architectures.
- **L-EXP-12** Mixed endianness (`types.py:76`).

### Exporters -- IDA

- **L-IDA-1** Support IDA 9.0 (P/E/I L/M/L); legacy versions before 9.0 (low priority given the maintenance burden). Depends on R-API-10.
- **L-IDA-2** Windows support (P/E/I M/M/L); currently experimental and untested.
- **L-IDA-3** Integrate the IDA export into "Produce file" > Quokka, like Ghidra's "Export" (P/E/I L/L/L).
- **L-IDA-4** Remove the `Layout.h` dependency from `writer.h`; remove `tid_t` from composite types and members.
- **L-IDA-5** Instruction decoding failure recovery (`src/Block.cpp:74`, `src/Reference.cpp:110`, `src/Layout.cpp:208`).
- **L-IDA-6** Imports: ELF vs PE import handling (`src/Function.cpp:170`); ordinal without a name (`include/quokka/Imports.h:37`).
- **L-IDA-7** Type and member comments are not exported (`src/api_v9/DataType.cpp:202,236,396`).
- **L-IDA-8** CFG block positions: not exported in headless mode (`src/Function.cpp:182-186`); decide what to do with them (issue #90).
- **L-IDA-9** Code debt: restore `ARM_SIMPLIFY` (`src/Quokka.cpp:301`); DB-load flag (`src/Quokka.cpp:341`); hashable/comparable types in `include/quokka/Bucket.h:255,324,392`; `Comment.h:69` location variant; `Logger.h:184`; `src/Writer.cpp:106`; `src/Layout.cpp:78`; references in `src/api_v8/DataType.cpp` (if v8 is kept); `spX` version parsing (`CMakeLists.txt:50`); `cmake/FindIdaSdk.cmake:361`.
- **L-IDA-10** Performance hot spots: `create_qflow_chart`, xref iteration, `next_unknown`.
- **L-IDA-11** "Use the new Hex-Rays plugin system" -- unsolved, to check. Evidence it may be covered: #118 added `ida-plugin.json` (HCLI schema, IDA 9.1-9.3, linux-x86_64 / macos) and issue #78 is closed. To check: plugin-center publication, Windows platform, alignment with R-API-10.

### Exporters -- Ghidra

- **L-GH-3** UI improvements (P/E/I M-L/L/M).

### Exporters -- BinaryNinja

- **L-BN-1** Native export menu entry, like Ghidra's "Export" (P/E/I L/L/L).
- **L-BN-2** Plugin-manager distribution requires a dedicated repository with `plugin.json` at its root.
- **L-BN-3** Write-back (`Program.commit()` raises `NotImplementedError`).

### Python

- **L-PY-1** Validate that the Python pcode generated code closely matches the original instructions (P/E/I M/M/M).
- **L-PY-2** Expose the memory layout (P/E/I M/H/M; `TODO(rd)` in `program.py`) and the CFG graph positions.
- **L-PY-3** Enum member iteration ergonomics: dict/list-like access instead of the current API (P/E/I L/L/M).
- **L-PY-4** `Function.get_instruction()` is a linear scan over all blocks; use a sorted structure or `_chunks` for O(log n) (P/E/I L/L/L; `function.py:305`).
- **L-PY-5** IDA sometimes merges two instructions into one; not handled (P/E/I L/M/L; `instruction.py:342`).
- **L-PY-6** Calling conventions: empty `floating_point_registers` for ARM64 and GOLANG (P/E/I L/L/L; `calling_convention.py:142,162`); check x86 `ST0`/`ST1` (`:64`); ARM stack pointer (`analysis/arch.py:231`).
- **L-PY-7** Check that `Block.__hash__` (proto index) is unique (`block.py:190`).
- **L-PY-8** Refactors, possibly already done by v1 -- verify and close:
    - Rewrite the Reference Manager: hard to understand, maintain and use, with performance issues; rewrite without losing functionality. No `ReferenceManager` class remains in Python.
    - Remove the interface for Function Chunks: an IDA abstraction users do not care about. No chunk class remains in Python (only the private `Function._chunks`).
    - Use `weakref` for `Program` back-refs so the garbage collector can reclaim parts of the program. Still open: only type members use `weakref`.
- **L-PY-9** Reference/lookup API design notes, review against the current API:
    - Xref kinds per object: `Data` -> xref_to/xref_from address; `Instruction` -> xref_to/xref_from address; `CompositeType` -> xref_from address.
    - Lookups: `program.get_function(address)`, `program.get_block(address)`, `function.get_instruction(address)`; explicitly NOT `program.get_instruction()` -- which exists today (and becomes a context manager with R-GIT-2).
    - Back-refs: `Instruction` -> `Function`, `Instruction` -> `Block`.
- **L-PY-10** Redesign the architecture recognition module (issue #13).

### Format and performance research

- **L-FMT-1** File size vs runtime performance: string table vs inline names; exporter memory when hoarding strings; user-selectable tradeoff vs a fixed middle ground. "No compression, let users compress" is superseded by LZMA (D-9).
- **L-FMT-2** Block instructions: one deduplicated instruction table with blocks holding indices, vs blocks holding instructions.
- **L-FMT-3** References: encode reference indices in the objects ("fast references, bigger file") vs the global table ("slow references, smaller file") as a user option; does not work in LIGHT mode. LIGHT-mode fail-fast: compare the per-block instruction count (`Block.n_instr`) when disassembling and warn on mismatch -- verify the warning exists.
- **L-FMT-4** Benchmarks (size and compression figures exist in upstream PR #88).

### Docs and tooling

- **L-DOC-1** Contextualized examples in the user documentation -- feedback from attendees (P/E/I L/M/M).
- **L-DOC-2** Decide the future of the docs: keep MkDocs or convert to Sphinx. Evaluate the current `docs/` structure; compare API reference autogen, theming, RTD hosting; if migrating, plan Markdown conversion, autodoc for the Python bindings, build/CI updates.
- **L-TOOL-1** Profiling tooling (perf script, Tracy): commit only on a dedicated branch and once production-ready.

### Ordering note

The previous task list was ordered by bang-for-buck and started with Ghidra UI (L-GH-3) and Ghidra decompilation (now done, D-16). This roadmap groups by release and places both after 1.0.0. Items L-PY-1 and R-API-7 were noted as moderate-to-quick wins, good candidates between larger tasks.

---

## 4. Known limitations

- IDA types from foreign/base type libraries (`is_from_subtil`) are exported as `TYPE_UNK`.
- Ghidra types that cannot be represented degrade to `TYPE_UNK` with a warning.
- Windows builds are experimental and untested.
