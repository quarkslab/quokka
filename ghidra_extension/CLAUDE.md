# Ghidra extension (Java) -- `ghidra_extension/`

Build/install/usage for humans: `README.md` here. This file: agent rules and internals.

## Rules

- Proto rules: `proto/CLAUDE.md`. Change the IDA exporter or Python consumer only when compatibility requires it
- Behavioral reference is the IDA exporter: aim for structurally equivalent output, not equal numbers; never validate against IDA `.quokka` fixtures (they are not Ghidra golden files)
- Develop and test against the Ghidra version of the `third_party/ghidra` submodule tag (minimum accepted by `build.gradle`: 12.0.3) (fetch it with `scripts/fetch_ghidra.sh`, which also takes `--dest`, `--force`, `--update-submodule [TAG]`)
- Version-specific quirks go in `compat/Compat.java` only
- Determinism: sort repeated fields before serialization (table below)
- Error model: hard error on invalid input, warning on degraded output, no silent fallbacks. Logs: FATAL / WARN (degraded artifact) / INFO / DEBUG
- Tests assert structural properties (ranges, minimums), never exact counts: Ghidra analysis changes between releases and differs from IDA

## Build facts

- JDK 21, Gradle wrapper (8.12), `GHIDRA_INSTALL_DIR` required; `buildExtension.gradle` comes from `$GHIDRA_INSTALL_DIR/support/`
- `./gradlew installExtension` = build + install into `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/` (removes the previous install; warns about a copy in the user settings dir). Clean `dist/` before `buildExtension`: stale zips conflict
- protobuf-java is `compileOnly`, pinned in `build.gradle` to the Ghidra runtime version; `org.tukaani:xz` is bundled (LZMA output)
- `quokkaVersion` in `build.gradle` -> generated `Version.java` (`generateVersion` task) -> `ExporterMeta.version`
- Headless export needs the extension installed (Ghidra's OSGi classloader ignores `CLASSPATH` for script deps)
- Javadoc for Ghidra APIs: `javadoc -sourcepath third_party/ghidra/Ghidra/Framework/SoftwareModeling/src/main/java -subpackages ghidra.program.model.data -classpath <all jars of $(scripts/fetch_ghidra.sh)>`

## Pipeline (`ExportPipeline.export()`)

```
1 Meta -> 2 Segments -> 3 Types -> 3b type-to-type refs -> 4 Functions
-> 5 References (+ attachInstructionXrefs) -> 6 Layout -> 7 Data (+ data xrefs)
-> headers (DataTypeWriter) -> 8 xz-compress + write
```

| File | Role |
|---|---|
| `QuokkaExporter.java` | GUI `File > Export`; options "Export Mode", "Export Decompiled C" |
| `ExportContext.java` | shared state; `resolveSegmentIndex/Offset`, `resolveFileOffset`, `resolveTypeIndex` |
| `export/MetaExporter` | mode, version, ISA, endianness, hash, backend `DISASS_GHIDRA` |
| `export/SegmentExporter` | MemoryBlocks 1:1, overlays excluded, BSS included; type: X -> CODE, uninitialized -> BSS, name contains "extern" -> EXTERN, else DATA; `file_offset` from SourceInfo else -1 |
| `export/TypeExporter` | primitives 0-8, then enums/composites/typedefs; `c_str` via `util/CTypeRenderer` |
| `export/FunctionExporter` | functions, blocks, edges (`SimpleBlockModel`); SELF_CONTAINED instructions/mnemonics/operands; optional decompilation (`DecompInterface`); `is_exported` via `isExternalEntryPoint()` |
| `export/ReferenceExporter` | ReferenceManager refs (FALL_THROUGH skipped), absolute-VA locations, per-instruction xrefs |
| `export/LayoutExporter` | R or X blocks only; uninitialized block = one DATA region (never byte-walked); else code-unit walk, adjacent same-type regions merged (CODE/DATA/GAP) |
| `export/DataExporter` | defined data, type indices, data xrefs |
| `util/*Mapper` | ISA, calling convention, RefType -> EdgeType, block type, function type (thunk -> THUNK, external -> IMPORTED, else NORMAL); `HashUtil` (FileBytes, disk fallback), `AddressUtil` |
| `src/script/ghidra_scripts/` | `QuokkaExportHeadless.java` (`--out=`, `--mode=`, `--decompiled`), `QuokkaApplyHeadless.java` (`--quokka=`; applies types, function names/prototypes/comments, data names/types/comments in one transaction; used by Python `commit()`) |

## Design decisions

- `SimpleBlockModel`, not `BasicBlockModel`: no split at CALL, matches IDA; blocks filtered to the function body
- Edge type by out-degree: 0 UNKNOWN, 1 UNCOND, 2 COND, 3+ INDIR (same as IDA `GetEdgeType()`)
- Block size = max - min + 1; `is_thumb` from the ARM `TMode` register; mangled name only when it differs from the display name
- External functions: `TYPE_IMPORTED`, EXTERNAL address space, `file_offset = -1`, no blocks
- Per-type `c_str`: custom `CTypeRenderer` (bitfields, function pointers, nested pointers/arrays). Never `DataType.toString()` (debug dump, not C); per-type `DataTypeWriter` is package-private and drags dependencies + preamble. `headers` uses bulk `DataTypeWriter`; `c_str` uses Ghidra display names (`byte`, `dword`, ...) and member types by name only, so it compiles only together with the `headers` preamble
- Unrepresentable Ghidra types -> `TYPE_UNK` with a warning

## Determinism

| Field | Sort key |
|---|---|
| Segments | start VA |
| Functions | entry VA |
| Blocks, Data | `(segment_index, segment_offset)` |
| References | `(source, destination, type)` |
| Types | primitives 0-8 fixed; the rest follows `getAllDataTypes()` order, NOT sorted (roadmap R-EXP-3) |

## Tests

- JUnit 4 (Ghidra test utilities are JUnit 4) + Mockito: `./gradlew test` (mappers, `CTypeRenderer`, `HashUtil`, `AddressUtil`, `ExportPipelineTest`); not run by CI (roadmap R-TEST-4)
- Python integration: `tests/python/tests/ghidra/` (export, CLI, apply-back); needs `GHIDRA_INSTALL_DIR` + installed extension, auto-skips otherwise
- CI `ghidra.yml` (push to main, PRs, tags; path-filtered): `installExtension` + Python apply-back tests; tags upload the extension zip
