# Usage

## Exporting a binary

Quokka supports three ways to generate `.quokka` files: the IDA plugin, the
Ghidra extension, and the `quokka-cli` command-line tool.

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

### CLI (`quokka-cli`)

Quokka provides a CLI utility tool to automatically export a single file or
all executable files of a given directory in parallel.
It supports both IDA Pro and Ghidra backends:

```commandline
$ quokka-cli --backend ghidra -t 8 dir/
$ quokka-cli --backend ida --ida-path /opt/ida -t 8 dir/
$ quokka-cli -t 8 dir/                          # auto-detect backend
```

Available options:

| Option | Description |
|--------|-------------|
| `--backend` | Disassembler backend: `ida`, `ghidra`, or `auto` (default: `auto`) |
| `--ida-path` | Path to IDA Pro installation (sets `IDA_PATH`) |
| `--ghidra-path` | Ghidra installation directory (sets `GHIDRA_INSTALL_DIR`) |
| `-t`, `--threads` | Number of parallel workers (default: 1) |
| `-m`, `--mode` | Export mode: `LIGHT` or `FULL` (default: `LIGHT`) |
| `--decompiled` | Enable decompiled code export (IDA only) |
| `-v`, `--verbose` | Enable verbose logging |

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

**LIGHT mode** focuses on exporting only essential information, producing fast
and lightweight files. No information at instruction level or below is exported;
the Capstone engine decodes instructions at runtime from the original binary
bytes.

**FULL mode** (self-contained) exports the full disassembly exactly as the
backend disassembler shows it. This produces heavier files but does not require
depending on third-party disassemblers at runtime.

Both modes expose the same Python API.

!!! warning
    From the self-contained mode it is still possible to obtain the Capstone
    instruction object, but the Capstone disassembly might differ from what
    Quokka exported (instructions might be split, merged, not supported, have
    different mnemonics, etc.). Different binary analysis platforms produce
    different disassembly -- keep this in mind when mixing Capstone with the
    self-contained mode.

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
