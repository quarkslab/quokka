# Structures

Structures exported from the disassembler are found in `program.structures`. A
structure is composed of its members and most of the information found in the
disassembler is extracted.

!!! note
    The type system includes structures, unions, enums, arrays, pointers,
    and typedefs. Use the `is_*` boolean properties (e.g. `t.is_struct`,
    `t.is_union`, `t.is_enum`) to check the kind of a type object.
    See the [Types](../../types.md) page for full details.

# Segments

The segments exported from the disassembler are available under `program.segments`

# Strings

Strings are accessible per-function via `func.strings`, per-block via
`block.strings`, and per-instruction via `inst.strings`. There is no
program-level `strings` property -- iterate over functions to collect all
strings in the binary.

# Executable

The executable file is accessible via `program.executable`. It provides methods
to read raw bytes, strings, and integers from the binary file using **file
offsets** (not virtual addresses). Use `program.address_to_offset(addr)` to
convert a virtual address to a file offset first.

