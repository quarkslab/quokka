FAQ
===

## What is `quokka`?

`quokka` is a tool to manipulate the exported versions of your program.
The goal is to have an easy to understand, stable and scalable API to query the
(disassembled) binary without relying on having a disassembler running in the
background nor interacting with its API.

As a bonus, once a binary has been exported, you can close the disassembler and
work only with the exported file.

## Which disassemblers are supported?

Quokka currently supports **IDA Pro** and **Ghidra** as disassembly backends.
Both produce the same `.quokka` protobuf files that the Python library can load.

## Why not use the disassembler API directly?

Disassembler APIs have at least two drawbacks:

* you need to learn the specific syntax and how it works:

```Python
# IDA way
inst = ida_ua.insn_t()
ida_ua.decode_insn(inst, 0xABCD)
print(inst.get_canon_mnem())

## Quokka
inst = program.get_instruction(0xABCD)
print(inst.mnemonic)
```

* you need a running instance of the disassembler, which requires a license
  and slows down batch analysis.

## How does `quokka` work?

In short, a disassembler plugin (IDA or Ghidra) serializes the analysis to a
binary protobuf format (`.quokka` files). The Python library then reads these
files and exposes the data through a clean object model.

## What is exported?

You may have a look at the protobuf format definition to understand exactly
what is exported but the list here can give you a nice overview.

### Exported features
* Meta information (file hash, name, detected compiler, calling convention)
* Segments
* Structures (structs, enumerations and unions)
* Comments (every comment attached to anything)
* Layout (where is the code/data/unknown)
* Functions and their associated Control Flow Graph
* Call Graph
* Instructions (and their operands / mnemonics)
* References (data and code xref)
* Data (bytes, strings, ...)
* Types (structures, enumerations, unions, arrays, pointers)
* Decompiled pseudocode (optional; IDA with Hex-Rays only)

## What are the trade-offs?

Currently only the LIGHT export mode is implemented. It produces small files
but requires the original binary and Capstone for instruction decoding at
runtime. A FULL (self-contained) mode that includes all instruction data in the
export is planned but not yet functional. See [Usage](usage.md#export-modes)
for details.

## Contributing

Every PR is welcome.

### Where to start?

Grep the code for TODO, some are easy, some require more understanding of the
code.

### Tips

During development, you may want to use a soft link in the
plugin directory coupled with the option to unload the plugin `PLUGIN_UNL`

```console
user@host:~/quokka/$ ln -sf $(pwd)/build/src/quokka*64.so \
    /opt/ida/plugins/
```
