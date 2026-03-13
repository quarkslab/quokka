# Usage

## Exporting a binary

Quokka supports multiple ways to generate `.quokka` files. The recommended
approach for most users is the `quokka-cli` command-line tool, which works with
both IDA Pro and Ghidra. For more control, you can use the IDA plugin or the
Ghidra extension directly.

### CLI (`quokka-cli`)

The `quokka-cli` tool is the easiest way to export binaries in headless mode.
It automatically detects available backends (IDA or Ghidra) and can export one
or more files and/or directories (all executable files in each directory) in
parallel.

```commandline
$ quokka-cli /path/to/binary                    # export a single file
$ quokka-cli -t 8 dir/                           # export a directory in parallel
$ quokka-cli --backend ghidra -t 8 dir/          # use Ghidra explicitly
$ quokka-cli --backend ida --ida-path /opt/ida -t 8 dir/  # use IDA explicitly
$ quokka-cli -t 8 dir1/ dir2/ bin1 bin2          # multiple inputs at once
```

Available options:

| Option | Description |
|--------|-------------|
| `-b`, `--backend` | Disassembler backend: `ida`, `ghidra`, or `auto` (default: `auto`) |
| `-i`, `--ida-path` | Path to the IDA installation directory (the folder containing `idat`) |
| `--ghidra-path` | Ghidra installation directory (overrides `GHIDRA_INSTALL_DIR`) |
| `-t`, `--threads` | Number of parallel workers (default: 1) |
| `-m`, `--mode` | Export mode: `light` or `full` (default: `light`) |
| `--decompiled` | Export decompiled code (IDA only) |
| `--timeout` | Timeout for each export in seconds |
| `--override` | Override existing `.quokka` files |
| `-o`, `--output` | Output path or template (default: `%F.quokka`). See [Output naming](#output-naming) below |
| `-v`, `--verbose` | Enable verbose logging |

!!! tip
    You can set the `IDA_PATH` environment variable (pointing to the IDA
    installation directory) and the `GHIDRA_INSTALL_DIR` environment variable
    instead of passing `--ida-path` / `--ghidra-path` every time.

#### Output naming

By default (when `-o` is not specified), the `.quokka` file is placed next to
the input binary with the same name plus a `.quokka` extension. For example,
exporting `/usr/bin/ls` produces `/usr/bin/ls.quokka`. More precisely, the
output path is resolved **relative to the input file's location**, not the
current working directory.

The `-o` option accepts either a literal path or a **template string** that is
expanded per file (useful in batch/directory mode). Template specifiers are
substituted based on the input binary path:

| Specifier | Meaning | Example (input: `/usr/bin/hello.elf`) |
|-----------|---------|---------------------------------------|
| `%f` | Filename without extension (stem) | `hello` |
| `%F` | Filename with extension | `hello.elf` |
| `%P` | Full absolute path including filename | `/usr/bin/hello.elf` |
| `%p` | Parent directory (absolute) | `/usr/bin` |
| `%e` | File extension without the dot | `elf` |
| `%%` | Literal `%` character | `%` |

Missing parent directories in the expanded path are created automatically.

```commandline
# Place output next to the binary (default behavior)
$ quokka-cli /usr/bin/ls                          # -> /usr/bin/ls.quokka

# Custom output directory, keeping the original filename
$ quokka-cli -o "/tmp/exports/%F.quokka" /usr/bin/ls  # -> /tmp/exports/ls.quokka

# Custom naming scheme in batch mode
$ quokka-cli -o "%p/quokka/%f_ghidra.quokka" -t 4 /usr/bin/
#   /usr/bin/ls      -> /usr/bin/quokka/ls_ghidra.quokka
#   /usr/bin/cat     -> /usr/bin/quokka/cat_ghidra.quokka

# Single file with a literal output path (no specifiers)
$ quokka-cli -o /tmp/my_export.quokka /usr/bin/ls # -> /tmp/my_export.quokka
```

### IDA Plugin

!!! note
    This requires a working IDA installation with the Quokka plugin installed.

#### GUI

Use the plugin shortcut inside IDA: (by default) **Alt+A**

#### Command line

```commandline
$ idat -OQuokkaAuto:true -A /path/to/hello.i64
```

!!! tip
    `idat` is used instead of `ida` to increase the export speed as the graphical
    interface is not needed.

#### IDA Export Options

To pass options to the IDA plugin, use the `-O` switch on the command line:
`-OQuokka<OPTION_NAME>:<OPTION_VALUE>`.

##### Log -- Log level

* Usage: `-OQuokkaLog:<LEVEL>`
* Values: Debug, _Info_, Error

This option controls the reporting level of the exporter.

Note: The debug log level also prints the line and the function.

##### File -- Output filename

* Usage: `-OQuokkaFile:<NAME>`
* Values: A path where the user is allowed to write

Use this option to override the file written by quokka.
If none is given, `<path_to_idb>.quokka` is used.

##### Auto -- Auto mode

* Usage: `-OQuokkaAuto:<true|false>`

Use this option to launch quokka directly from the command line.

##### Decompilation

* Usage: `-OQuokkaDecompiled:<true|false>`

Use this option to also export decompiled code in the resulting export.

##### Export Level

* Usage: `-OQuokkaMode:<MODE>`
* Values: `LIGHT`, `FULL`

Controls the export level for the instructions:

* **Light** mode: only block boundaries are exported. Instructions are decoded
  at runtime by Capstone from the original binary bytes.
* **Full** mode: the instruction mnemonics, operands, and their string
  representation are exported directly. The original binary is not required
  for disassembly at analysis time.

Both modes expose the same Python API.

### Ghidra Extension

!!! note
    This requires a Ghidra installation with the QuokkaExporter extension installed.

#### GUI

1. Open a binary in Ghidra's CodeBrowser
2. File > Export Program
3. Select **Quokka** format
4. Choose output file
5. Click Export

#### Headless

```commandline
$ analyzeHeadless /tmp/proj Test \
    -import /path/to/binary \
    -scriptPath ghidra_extension/src/script/ghidra_scripts \
    -postScript QuokkaExportHeadless.java \
    --out=/path/to/output.quokka --mode=LIGHT
```

!!! note
    The Ghidra extension must be installed into `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/`
    for headless export to work.

### Python API

You can also trigger an export programmatically:

```python
import quokka
from quokka.types import Disassembler

# Export and load in one step (auto-detects backend)
prog = quokka.Program.from_binary("/path/to/binary")

# Explicitly choose a backend
prog = quokka.Program.from_binary(
    "/path/to/binary",
    disassembler=Disassembler.GHIDRA,
)

# Export only (no Program returned)
path = quokka.Program.generate("/path/to/binary", output_file="out.quokka")
```

## Loading an export file

```python
import quokka

# From an already-exported .quokka file
prog = quokka.Program("binary.quokka",  # the exported file
                      "binary")          # the original binary
```

The original binary is needed because Quokka reads raw bytes from it at runtime
(e.g. for instruction decoding in LIGHT mode). The binary must be the exact same
file used during export -- Quokka checks the hash on load.

## Export Modes

Quokka offers two export modes: **LIGHT** and **FULL** (also called
self-contained).

!!! warning
    Only **LIGHT** mode is currently implemented. FULL mode is planned but not
    yet functional.

**LIGHT mode** focuses on exporting only essential information, producing fast
and lightweight files. No information at instruction level or below is exported;
the Capstone engine decodes instructions at runtime from the original binary
bytes.

**FULL mode** (self-contained) will export the full disassembly exactly as the
backend disassembler shows it. This will produce heavier files but will not
require depending on third-party disassemblers at runtime.

Both modes will expose the same Python API.

|  | Light Mode | Self-contained Mode |
| -------- | -------- | -------- |
| Functions | Yes | Yes |
| Basic Blocks | Yes | Yes |
| Instructions | No | Yes |
| Operands | No | Yes |
| Data References | Yes | Yes |
| Cross References | Yes | Yes |
| Sections/Layout | Yes | Yes |
| Decompilation | Optional | Optional |
