# Features

**Quokka** exports as much information from the disassembler (IDA Pro or Ghidra) as possible. Both backends produce `.quokka` files with the same protobuf schema, but they differ in a few areas.

## Export modes

Quokka supports two export modes that control how much detail is written to the `.quokka` file:

- **Light** -- only block-level information is exported. Instructions are decoded at runtime by [Capstone](https://www.capstone-engine.org/) from the original binary bytes.
- **Full** (self-contained) -- instructions, operands, and their string representations are exported directly. The original binary is not strictly required for disassembly at analysis time.

Both modes expose the **same Python API**.

!!! warning
    The **Full** export mode is produced by the Ghidra and Binary Ninja exporters; the IDA plugin currently produces Light exports only.

## Exported elements

The table below shows what each backend exports in each mode.

| Category | Feature | IDA | Ghidra |
|----------|---------|:---:|:------:|
| **Metadata** | Binary name | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Architecture / ISA | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Compiler | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Layout** | Segments | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Code layout (code/data/gap regions) | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Functions** | Name, type, boundaries | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Prototype / calling convention | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Decompiled pseudocode | :material-check:{ .icon-green title="Requires Hex-Rays" } | :material-check:{ .icon-green title="Extension option / headless --decompiled" } |
| **Basic Blocks** | Address, size, type | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Instruction count | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Instructions** | Mnemonic, operands, bytes | :material-close:{ .icon-red title="Decoded at runtime by Capstone" } | :material-check:{ .icon-green title="Full mode only" } |
| **Graphs** | Call graph | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | CFG (per function) | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Cross-references** | Code refs (call, jump) | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Data refs | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Data** | Address, type, size, name | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Strings** | Address and content | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Symbols** | Name, value, type | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| **Comments** | Function and instruction comments | :material-check:{ .icon-green } | :material-close:{ .icon-red } |
| **Data Structures** | Structs / unions | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Enumerations | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Arrays, pointers, typedefs | :material-check:{ .icon-green } | :material-check:{ .icon-green } |
| | Type-to-type cross-references | :material-check:{ .icon-green } | :material-check:{ .icon-green } |

!!! note
    Even in **Light** mode, instructions are still available through the Python API -- they are decoded transparently by Capstone when you access them. The "Instructions" row above refers to whether the exporter writes them into the `.quokka` file.

!!! note
    **Decompiled pseudocode** must be explicitly enabled: IDA needs Hex-Rays (`-OQuokkaDecompiled:true` or `quokka-cli --decompiled`); Ghidra uses the extension's "Export Decompiled C" option or the headless script's `--decompiled` (not yet passed through by `quokka-cli`).

!!! note
    Binary Ninja exports are not covered by this table yet.

## Other features

To ease **Quokka** usage in various workflows, the tool also provides several additional features:

* [Capstone](https://www.capstone-engine.org/) integration for transparent instruction decoding
* [Pypcode](https://github.com/angr/pypcode) integration (optional) for P-code based analysis
* Function annotation and write-back to the disassembler database (`prog.commit()`, IDA and Ghidra)
* User-defined type injection (`prog.add_type()`)
* CLI tool (`quokka-cli`) for batch export with both backends, with custom output naming via `-o`
