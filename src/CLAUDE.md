# IDA plugin (C++20) -- `src/`, `include/quokka/`

Build/install how-to for humans: `docs/installation.md`. This file: agent rules and internals.

## Scope

- Supported now (P0): IDA >= 9.1 (`ida-plugin.json`). Later: P1 IDA 9.0, P2 IDA 7.x/8.x. Keep designs portable, but do NOT write code for IDA <= 9.0 (`api_v8/`, SDK < 8.5 paths are legacy; roadmap R-API-10)
- C++20 only; format with `clang-format` (`.clang-format`)

## Build

- Needs CMake >= 3.13, Ninja, system **liblzma** (`find_package(LibLZMA REQUIRED)`), and **ccache** (auto-detected; configure must print `-- Enable compiler cache`, otherwise fix it first)
- FetchContent deps: abseil 20250127.0, protobuf v30.2, GoogleTest (with `-DBUILD_TEST=On`)
- Out-of-source only (machine-specific limits such as `-j`: `.claude/CLAUDE.local.md`); default build type Debug; `ccache` or `sccache` (`ccache -s` for stats)
- Use the fixed dirs `build-debug/` / `build-release/`; only `cmake --build` them. Never wipe or `--fresh` them (destroys ccache/FetchContent caches)
- IDA >= 9.2 (SDK submodule): `cmake -B build-debug -S . -G Ninja -DIDA_VERSION=9.3 -DCMAKE_BUILD_TYPE=Debug`
- IDA < 9.2: `-DIdaSdk_ROOT_DIR=/path/to/sdk` instead of `-DIDA_VERSION`
- Other options: `-DBUILD_TEST=On`, `-DENABLE_SANITIZER=On` (ASan; `LD_PRELOAD` it under IDA), `-DNO_BUILD=On` (skip plugin and protobuf; with `BUILD_TEST` only abseil + GoogleTest are fetched; no SDK needed), `-DNO_DEPRECATED=On` (`NO_OBSOLETE_FUNCS`)
- `cmake --install <dir>`: stages to `<dir>/quokka-install/`, copies to `~/.idapro/plugins/` (and `${IDA_ROOT_DIR}/plugins` if set)
- macOS: system Apple Clang (no Homebrew LLVM pin)
- `include/quokka/Version.h.in` -> generated `Version.h` (`GetVersion()`)
- C++ tests: `tests/CLAUDE.md`

## Export pipeline (`ExportBinary()`, `src/Quokka.cpp`)

```
WriteExporterMeta -> ExportMeta -> ExportSegments -> ExportFunctions (decompiler runs here)
-> WriteHeaders -> ExportEnums -> ExportCompositeDataTypes -> ExportTypedefs
-> ResolveDeferredSymbolXrefs -> ExportLinearScan (layout, data, references)
-> WriteFunctions -> SerializeToOstream through LzmaStreambuf (xz)
```

- `Export*()` read the IDA database; `Write*()` build protobuf (`src/Writer.cpp`)
- Types are exported after functions so decompiler-created types are captured; typedefs after composites so their targets exist; TID xrefs are deferred until types exist
- Singletons populated during export: `Settings` (mode, decompilation flag), `Segments`, `DataTypes`, `References`

## Entry points

- Interactive: `plugmod_t` (`plugin_ctx_t` -> `PluginInit()`; SDK <= 7.4 uses classic init/term/run), shortcut **Alt+A**; IDC function `quokka`
- Headless: `-OQuokkaAuto:true` + `-OQuokkaMode:{LIGHT|SELF_CONTAINED}` `-OQuokkaFile:<path>` `-OQuokkaDecompiled:{true|false}` `-OQuokkaLog:{DEBUG|INFO|ERROR}`; parsed by `GetArgument()` / `GetBoolArgument()`, run from `UIHook()`
- HCLI plugin manifest: `ida-plugin.json` (versions, platforms; no Windows)

## Layout

- `src/*.cpp` one file per artifact: `Function` (functions, `qflow_chart_t` blocks, edges, `is_exported`), `Block`, `Data`, `DataType` (types from `til_t`), `Reference` (`GetXrefType()`), `Layout` (linear scan), `Segment`, `FileMetadata` (ISA, hash, endianness), `Imports`, `Writer`, `Util`
- Not built: `Comment.cpp`, `Instruction.cpp`, `api_v*/Data.cpp` (commented out)
- Version-specific code: `src/api_v8/`, `src/api_v9/`, selected by `#if IDA_SDK_VERSION < 850` includes in the sources (not by CMake)
- `include/quokka/`: `Compatibility.h` (include before any IDA header; `<cstdint>` fix, `BADADDR64`), `ProtoWrapper.h`, `Bucket.h` (dedup containers `SetBucket`/`MapBucket`/`MultiMapBucket`, frequency-sorted), `ProtoHelper.h` (`ref_count` + `proto_index`), `LzmaStreambuf.h`, `Logger.h` (`QLOG_*`), `Util.h`
- 64-bit only for SDK >= 8.5 (handled in `src/CMakeLists.txt`)

## Linear scan (`Layout.h` `HeadIterator`)

- Walks `[start_ea, max_ea)` once with `next_head()` / `next_unknown()`, emitting CODE/DATA/GAP/UNK regions
- Invariants: `next_head_addr > current_ea`; `next_unk_addr > current_ea`; `next_chunk_addr` may equal `current_ea`; `next_ea` may be `max_ea`

## Type handling

- Typedef targets: `get_next_type_name()` for chains and typedefs over struct/union/enum; over array/pointer/primitive the info is embedded (`array_type_data_t`, `ptr_type_data_t`, `get_real_type()`)
- `is_typeref()` is true for every named type reference; only `is_typedef()` is a real C typedef
- Type-to-type xrefs: IDA has no API; `EmitTypeToTypeRef()` (`api_v9/DataType.cpp`, called from `ExportCompositeMembers`, `ExportPointer`, `ExportArray`, `ExportSingleTypedef`) records member types, pointer/array elements, typedef targets as `EDGE_DATA_READ` references: source type `xref_from` + target `xref_to`, plus the member's `xref_from` for struct/union members

## Pitfalls

- Stale IDA databases: an existing `<binary>.i64` is silently reused (stale types/analysis); leftover `.id0/.id1/.id2/.til/.nam` raise `StaleIDBError` in Python. Export from a clean temp folder
- Hidden segments (HEADER, `.reloc`) are exported, only ephemeral ones skipped -- the linear scan crashes on addresses outside known segments (#115)
- ARM: `UnsimplifyARM()` disables IDA's ARM simplification to get raw mnemonics
- Hex-Rays: needs `HAS_HEXRAYS` at build time and `init_hexrays_plugin()` at runtime
- SELF_CONTAINED is not implemented: `WriteBlock()` asserts (roadmap L-EXP-1)
- No fallback output path: an unwritable output fails the export
- Perf hot spots: `create_qflow_chart` (per function), xref iteration (`xrefblk_t`), `next_unknown`, `get_aflags` (via `has_xref` in the linear scan); IDA `auto_wait` dominates wall time; many SDK calls are inlined, so their cost shows under the plugin, not `libida.so`
