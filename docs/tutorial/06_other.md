# Structures

Structures exported from IDA are found in `program.structures`. A structure is 
composed of his members and most of all the information found in IDA are extracted.

!!! note
    `Unions`, `enums` and `structures` are all merged into the more generic 
    term structure in Quokka. The structure type is found in `structure.type`.

# Segments

The segments exported from IDA are available under `program.segments`

# Strings

All the strings of the binary are also listed in `program.strings`.

# Executable

The executable file is best dealt with the `program.executable` attribute. 
Methods are provided to read from the  file content at both absolute and 
relative address.

