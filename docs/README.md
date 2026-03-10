# Quokka: A Fast and Accurate Binary Exporter

## Introduction

Quokka is a binary exporter: from the disassembly of a program, it generates
an export file that can be used without the disassembler. It currently supports
**IDA Pro** and **Ghidra** as disassembly backends.

The main objective of **Quokka** is to enable to completely manipulate the
binary without ever opening a disassembler after the initial export. Moreover, it
abstracts the disassembler's API to expose a clean interface to the users.

Quokka is heavily inspired by [BinExport](https://github.com/google/binexport),
the binary exporter used by BinDiff.

## Architecture

```
     IDA Pro                Ghidra
        |                      |
IDA Plugin (C++)    Ghidra Plugin (Java)
        |                      |
        +--- quokka.proto -----+
          (protobuf schema)
                   |
             .quokka files
                   |
   Python bindings (quokka.Program)
   +-- Capstone backend (primary)
   +-- Pypcode backend (optional)
```

## Installation

### Python library

```commandline
$ pip install quokka-project
```

### Disassembler plugins

The IDA and Ghidra plugins are only needed to **generate** `.quokka` files.
Reading them requires only the Python library above.

- **IDA Plugin** -- pre-built libraries available in [Releases](https://github.com/quarkslab/quokka/releases). Get the file named `quokka_plugin**.so`.
- **Ghidra Extension** -- see the [Ghidra extension README](https://github.com/quarkslab/quokka/tree/main/ghidra_extension) for build and install instructions.

For more details see [Installation](installation.md).

## Quick Start

### Loading an export file

`Program.from_binary()` invokes a disassembler to export and load the binary in
one step. It requires the appropriate environment variable to locate the
disassembler:

- **IDA**: set `IDA_PATH` to the IDA installation directory
- **Ghidra**: set `GHIDRA_INSTALL_DIR` to the Ghidra installation directory

```python
import quokka
from quokka.types import Disassembler

# Directly from the binary (auto-detects available backend)
ls = quokka.Program.from_binary("/bin/ls")

# Explicitly choose a backend
ls = quokka.Program.from_binary("/bin/ls", disassembler=Disassembler.GHIDRA)
ls = quokka.Program.from_binary("/bin/ls", disassembler=Disassembler.IDA)

# From an already-exported file
ls = quokka.Program("ls.quokka",  # the exported file
                    "/bin/ls")    # the original binary
```

### Exploring the binary

```python
# Functions
func = prog.get_function("main")
print(func.name, hex(func.start), len(func), "blocks")

# Basic blocks and instructions
for block in func.values():
    for addr, inst in block.items():
        print(f"  0x{addr:x}: {inst.mnemonic}")

# Cross-references
for callee in func.callees:
    print(f"  calls {callee.name}")

# Strings
for s in func.strings:
    print(repr(s))
```

### Editing and adding types

```python
# Add new types from C declarations
prog.add_type("struct context { int id; char name[64]; };")
prog.add_type("enum status { OK=0, ERROR=1 };")

# Save the .quokka file
prog.write()

# Or apply changes (including new types) back to the IDA database
prog.commit(database_file="ls.i64", overwrite=True)
```

See the full [editing documentation](write_feature.md) for details on renaming
functions, setting prototypes, and more.

## Building

See the [Installation](installation.md) page for full build instructions for
both the IDA plugin and Ghidra extension.
