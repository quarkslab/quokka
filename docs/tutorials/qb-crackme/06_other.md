# Structures

Structures exported from the disassembler are found in `program.structures`. A
structure is composed of its members and most of the information found in the
disassembler is extracted.

!!! note
    `Unions`, `enums` and `structures` are all merged into the more generic 
    term structure in Quokka. The structure type is found in `structure.type`.

# Segments

The segments exported from the disassembler are available under `program.segments`

# Strings

All the strings of the binary are also listed in `program.strings`.

# Executable

The executable file is best dealt with the `program.executable` attribute. 
Methods are provided to read from the  file content at both absolute and 
relative address.

