# Protobuf schema (`proto/quokka.proto`) -- stable contract, high stakes

## Change rules

1. Never renumber fields; never reuse removed numbers
2. Prefer additive changes (new optional fields, new enum values)
3. Update every exporter (IDA `src/Writer.cpp`, Ghidra `ghidra_extension/`, Binary Ninja `binaryninja_extension/`) and the Python bindings
   - New enum value: also map it in each exporter's `*ToProto` / mapper and in Python `types.py` `from_proto()`
4. Backward-incompatible change = major version bump of all components (bump list in `.claude/CLAUDE.md`)
5. Unsure whether it breaks compatibility -> assume it does, propose a migration plan

## Code generation

| Consumer | How | Runtime pin |
|---|---|---|
| C++ (IDA) | `proto/CMakeLists.txt` target `quokka_proto` (also generates Python) | protobuf v30.2, abseil 20250127.0 (`CMakeLists.txt`) |
| Python | `pip install .` (`setup.py` `build_py`) runs `grpc_tools.protoc` -> `bindings/python/quokka/quokka_pb2.py` (generated, gitignored, never edit) | `protobuf>=7.35,<8`, `grpcio-tools` pinned in `pyproject.toml` |
| Ghidra | Gradle protobuf plugin; `src/main/proto/quokka.proto` is a symlink | protobuf-java = Ghidra runtime version (`build.gradle`) |
| Binary Ninja | `generate_proto.py` -> committed `bn_quokka/quokka_pb2.py`, CI freshness guard | see `binaryninja_extension/README.md` |

## Invariants

- On disk: xz/LZMA-compressed protobuf (all exporters); Python also reads raw protobuf
- Addressing is **segment-relative**: `segment_index` + `segment_offset`, plus `file_offset` (-1 if not in file) on `Function`, `Block`, `Data`; Python converts with `Program.virtual_address()`
- `types[]` index layout (PINNED):
  | Indices | Content |
  |---|---|
  | 0-8 | primitive `BaseType` in enum order: UNK, B, W, DW, QW, OW, FLOAT, DOUBLE, VOID -- never reorder |
  | 9.. | enums and composites (struct, union, pointer, array, typedef); IDA writes enums, then composites, then typedefs; other exporters may interleave (roadmap R-EXP-3) |
- Typedef = `CompositeType` with `TYPE_TYPEDEF`; `element_type_idx` = single-step alias target (chains resolved by the reader). Members reference resolved types, not typedefs. Types from foreign/base libraries -> `TYPE_UNK`
- `Type.is_new`: user-added type (Python `Program.add_type`), to be applied back to the database; meaningful for non-primitives only
- Modes: LIGHT = blocks carry `size` + `n_instr`, instruction-level tables empty (`instructions`, `operands`, `mnemonics`, `operand_strings`, `Block.instruction_index`); SELF_CONTAINED = `Block.instruction_index` into `instructions[]`
- Hash: `meta.hash` carries `hash_type` (SHA256 or MD5) + lowercase hex of the on-disk file; readers must honor `hash_type` (IDA prefers MD5)

## References

- `Reference{source, destination: Location, reference_type: EdgeType}`; `Location` = address or `DataTypeIdentifier{type_index, member_index}` (type-to-type refs use it on both ends)
- `xref_to` = incoming, `xref_from` = outgoing; both index `references[]`; members carry their own `xref_to` / `xref_from`
- Blocks store per-instruction refs as `(instr_bb_idx, xref_index)` pairs

## v0 -> v1 (basis for migration notes, roadmap R-DOC-3)

- `meta.backend` {name, version}; no global base address (segment-relative addressing instead)
- Segments: `virtual_addr` instead of start address
- Chunks and fake blocks removed: `Function` has `blocks[]` + `edges[]` (indices into its blocks; `user_defined` flag); blocks have `size`, `is_thumb`
- `Structure` replaced by `CompositeType` (struct/union/array/pointer/typedef) + `EnumType`; `Data` has `type_index`, no value
- Operands: type + optional value + optional backend-specific bytes
- Comments stored inline (not in the string table), attachable to instructions, functions, data (and members), types (and members)
- References refactored: typed (code/data) source -> destination (instruction, data, type member)
