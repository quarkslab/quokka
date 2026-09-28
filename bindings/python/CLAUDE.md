# Python bindings -- `bindings/python/quokka/`

User API and CLI docs: `docs/` (`usage.md` has every `quokka-cli` option, `write_feature.md` covers edits + `quokka-apply`). This file: internals and rules.

## Setup and standards

- Python >= 3.10; `pip install -e '.[dev]'` (extras: `test`, `pypcode`, `doc`, `dev`); `pip install .` regenerates `quokka_pb2.py`
- Runtime deps (`pyproject.toml`): capstone, networkx, `protobuf>=7.35,<8`, python-magic (`-bin` on Windows), click, idascript
- Format `black`, lint `flake8` (the `dev` extra; no ruff/nox config in the repo)
- Public API: everything exported by `quokka/__init__.py`; keep it stable. LIGHT and SELF_CONTAINED expose the same API

## Layout

| Path | Role |
|---|---|
| `program.py` | `Program(dict)`: start address -> `Function`; load, export orchestration (`generate`, `from_binary`), edits (`add_type`, `write`, `commit`, `regenerate`) |
| `function.py` | `Function(dict)`: block address -> `Block`, CFG (`graph`), callees/callers, editable name/prototype/comments/edges |
| `block.py` | `Block`: address -> `Instruction`; decodes in `__init__` (capstone in LIGHT, proto indices in SELF_CONTAINED) |
| `instruction.py` | `Instruction`, `Operand` |
| `data.py` | `Data`, `DataHolder` (sorted index; `prev`/`next` by bisect) |
| `data_type.py` | type hierarchy (below) |
| `types.py` | shared enums with `from_proto()` (`ExporterMode` LIGHT / FULL = proto `MODE_SELF_CONTAINED`, `Disassembler`, `RefType`, `Perm`, ...) |
| `exc.py` | `QuokkaError` and subclasses (`StaleIDBError`, `FunctionMissingError`, `NotInFileError`, ...) |
| `segment.py`, `executable.py`, `utils.py`, `version.py` | segments, raw file reader, hashing/helpers, `__version__` |
| `backends/` | `capstone.py` (LIGHT decoding), `pypcode.py` (optional P-code via lazy `Block.pcode_insts` / `Instruction.pcode_insts`), `ida/` (apply-back package: `apply_quokka()`; `apply.py` = IDAPython script run by `idascript`) |
| `analysis/` | arch, calling conventions, env, replacer |
| `__main__.py` | `quokka-cli` (`main`) and `quokka-apply` (`apply_changes`) |

## Loading model

- `Program.__init__`: read file (LZMA first, raw protobuf fallback) -> major-version check (warning) -> hash check (`QuokkaError` on mismatch) -> arch detection -> `Executable` -> `DataHolder` -> one `Function` per proto function (metadata only)
- Blocks are lazy: `Function.__getitem__` builds and caches a `Block` on first access; `values()`, `items()`, `blocks`, `instructions`, `get_instruction()`, `end` all trigger it; nothing is ever unloaded
- Never build blocks (proto / `_chunks` only): `graph`, `callees`, `callers`, `bytes`, `in_function()`, `in_degree`, `out_degree`, name/type/prototype/comments
- `keys()` / `len()` come from `_block_data`, but `in`, iteration and `==` use the dict content (roadmap R-PY-11). Explicit load/unload is planned (R-GIT-2)
- Types are lazy: `Program.get_type(index)`, cached in `Program._types`

## Types (`data_type.py`)

```
CoreType
+-- BaseType (IntEnum)            primitives, proto indices 0-8
+-- ComplexType                   proto, name, size, c_str, xrefs
    +-- EnumType                  members: name -> EnumTypeMember
    +-- StructureType (dict)      members: bit offset -> StructureTypeMember
    |   +-- UnionType             all members at offset 0, keyed by index
    +-- ArrayType / PointerType   element_type / pointed_type
    +-- TypedefType               aliased_type, resolve() through chains
```

- Positional member access: `member_at()` (dict keys are bit offsets); `Program.get_type_reference()` relies on it
- Type-to-type xrefs: `type_refs_from` / `type_refs_to` on `ComplexType` and `StructureTypeMember`; `EnumTypeMember` only `type_refs_to` (no `xref_from` in proto)
- `add_type(c_str)` appends a dummy type with `is_new=True`; the backend rebuilds it from `c_str` on apply-back

## Export and apply-back

- Backend auto-detection: IDA if `idascript` finds IDA (`IDA_PATH`), else Ghidra if `GHIDRA_INSTALL_DIR`; no Binary Ninja path (roadmap R-PY-9)
- IDA export: `idascript` + `idat -O...` flags; an existing `.i64` is opened instead of the binary; leftover `.id0/.id1/.id2/.til/.nam` -> `StaleIDBError`; without `override`, `generate()` silently returns an existing `.quokka` instead of exporting
- Ghidra export: `analyzeHeadless -postScript QuokkaExportHeadless.java`; temp project unless `database_file` given; `decompiled` is ignored with a warning although the extension supports it (roadmap R-PY-14); extension found in `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/` or the user settings dir
- Timeouts: `generate` / `commit` / `regenerate` 600 s; `from_binary` and CLI 0 (none)
- `commit()` returns the error count: IDA via `backends/ida` (default db `<exec>.i64`, takes a snapshot first, clears Hex-Rays cache); Ghidra via `QuokkaApplyHeadless.java` (project `.gpr`/dir, default `<exec>.ghidra`, needs `overwrite=True` for an existing project); Binary Ninja -> `NotImplementedError`
- `write()` saves uncompressed protobuf (exporters write LZMA; roadmap R-PY-12)

## Pitfalls

- Hash mismatch: the binary must be the exact file that was exported
- Capstone vs exporter instruction count mismatch in LIGHT mode is only logged at debug level
- Never edit `quokka_pb2.py`
