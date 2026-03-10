# Program & Metadata

The `Program` object is the root of every Quokka analysis. This page covers how to load a program, navigate its metadata, and explore the binary structure.

## The `Program` Object

`Program` is a Python `dict` subclass:

- Keys: **function start addresses** (`int`)
- Values: **`Function`** objects

```python
import quokka

prog = quokka.Program("bash.quokka", "bash")

# Dict-like access
func = prog[0x401000]          # by address
func = prog.fun_names["main"]  # by name

# Iteration
for addr, func in prog.items():
    print(f"0x{addr:x}: {func.name}")

len(prog)  # number of functions
```

## Loading Options

```python
# Option 1: direct load (you already have the .quokka file)
prog = quokka.Program("binary.quokka", "binary")

# Option 2: from_binary (invokes IDA automatically)
prog = quokka.Program.from_binary(
    exec_path="binary",
    mode=ExporterMode.LIGHT,  # default
    decompiled=False,
)

# Option 3: generate only (no Program returned)
path = quokka.Program.generate("binary", output_file="out.quokka")
```

!!! note
    `from_binary` requires a working disassembler installation: either IDA
    with the Quokka plugin, or Ghidra with the QuokkaExporter extension.
    Set the `disassembler` parameter to choose, or let it auto-detect.

## Program Metadata

```python
# Binary identity
prog.name           # "bash"  (from IDA)
prog.hash           # "a4f3..." (sha256 or MD5)

# Architecture
prog.isa            # ArchEnum.X86
prog.address_size   # 64 (bits)
prog.arch           # <class 'X86_64'>
prog.endianness     # Endianness.LITTLE_ENDIAN

# Disassembler that produced the export
prog.disassembler         # Disassembler.IDA
prog.disassembler_version # "9.0"

# Export mode
prog.mode           # ExporterMode.LIGHT

# Base address (lowest segment start)
prog.base_address   # 0x400000
```

## Supported Architectures

Quokka leverages Capstone for runtime disassembly, so it supports all architectures Capstone handles:

| Architecture | ISA enum |
|-------------|----------|
| x86 / x86-64 | `X86` |
| ARM / AArch64 | `ARM`, `AARCH64` |
| MIPS | `MIPS` |
| PowerPC | `PPC` |
| SPARC | `SPARC` |
| RISC-V | `RISCV` |

```python
from quokka.analysis import ArchEnum

prog.isa == ArchEnum.X86   # True for x86/x86-64
```

## Segments

Segments model the binary's memory layout (`.text`, `.data`, `.bss`, etc.)

```python
# Dict: segment_id → Segment
for seg_id, seg in prog.segments.items():
    print(f"[{seg_id}] {seg.name:15s}  "
          f"0x{seg.start:x}–0x{seg.end:x}  "
          f"type={seg.type}  "
          f"perm={seg.permissions}")
```

```
[0] .text            0x401000–0x4b2000  type=CODE  perm=R|X
[1] .rodata          0x4b2000–0x4c0000  type=DATA  perm=R
[2] .data            0x4c1000–0x4c5000  type=DATA  perm=R|W
[3] .bss             0x4c5000–0x4c8000  type=BSS   perm=R|W
```

```python
# Find the segment containing an address
seg = prog.get_segment(0x401234)
seg.in_segment(0x401234)  # True
```

## Finding Functions

```python
# By address (dict key)
func = prog[0x401000]

# By exact name (default)
func = prog.get_function("main")

# By partial name (first match containing the substring)
func = prog.get_function("parse", approximative=True)

# Restrict to NORMAL functions (skip imports/thunks)
func = prog.get_function("malloc", normal=True)

# The fun_names dict (name → Function)
for name, func in prog.fun_names.items():
    print(name)
```

## Reading Raw Bytes

```python
# Address → file offset
offset = prog.address_to_offset(0x401234)

# Read raw bytes from virtual address
raw = prog.read_bytes(0x401234, 16)
print(raw.hex())  # 'deadbeef...'
```

Useful for manual disassembly, hashing function bodies, or verifying data patterns.

## The `Executable` Class

`prog.executable` wraps the raw binary file (read entirely into memory at load time).

All methods work with **file offsets** — use `prog.address_to_offset(addr)` to convert a virtual address.

| Method | Returns | Description |
|--------|---------|-------------|
| `read_bytes(offset, size)` | `bytes` | Raw bytes at offset |
| `read_string(offset, size=None)` | `str` | UTF-8 string (null-terminated if no size) |
| `read_int(offset, size, signed=False)` | `int` | Integer, endianness-aware |
| `read_type_value(offset, type)` | `TypeValue` | Typed read (int, float, struct, enum, pointer…) |

```python
exe = prog.executable
offset = prog.address_to_offset(0x4b2010)

exe.read_bytes(offset, 4)            # b'\x48\x65\x6c\x6c'
exe.read_string(offset)              # "Hello"  (null-terminated)
exe.read_int(offset, 4)              # 0x6c6c6548  (little-endian)
exe.read_type_value(offset, some_type)  # dispatches by type kind
```

!!! tip
    `prog.read_bytes(v_addr, size)` is a convenience wrapper: it converts the virtual address to a file offset then calls `executable.read_bytes`.

## Call Graph (Program Level)

```python
import networkx as nx

# Lazily computed on first access
cg = prog.call_graph   # networkx.DiGraph

# Nodes are function start addresses
# Edges represent call relationships

# Most called functions (in-degree)
top_called = sorted(cg.in_degree(), key=lambda x: x[1], reverse=True)
for addr, degree in top_called[:10]:
    print(f"{prog[addr].name:30s}  called {degree} times")
```

## Quick Reference

| Concept | Code |
|---------|------|
| Load | `quokka.Program("f.quokka", "f")` |
| Architecture | `prog.arch`, `prog.isa`, `prog.endianness` |
| Segments | `prog.segments` |
| Find function by address | `prog[addr]` |
| Find function by name | `prog.get_function("name")` |
| Call graph | `prog.call_graph` (networkx DiGraph) |
| Raw bytes | `prog.read_bytes(addr, size)` |
| Binary file access | `prog.executable.read_bytes/string/int/type_value(offset, ...)` |
| Add a new type | `prog.add_type("struct foo { int x; };")` |
| Save `.quokka` only | `prog.write()` |
| Apply edits to IDA | `prog.commit(database_file="f.i64", overwrite=True)` |
| Commit + re-export | `prog.regenerate(database_file="f.i64", overwrite=True)` |
