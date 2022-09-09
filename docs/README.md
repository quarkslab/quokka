# Quokka: A Fast and Accurate Binary Exporter

## Introduction

Quokka is a binary exporter: from the disassembly of a program, it generates
an export file that can be used without the disassembler.

The main objective of **Quokka** is to enable to completely manipulate the
binary without ever opening a disassembler after the initial step. Moreover, it
abstracts the disassembler's API to expose a clean interface to the users.

Quokka is heavily inspired by [BinExport](https://github.com/google/binexport),
the binary exporter used by BinDiff.

## Installation

### Python plugin

The plugin is built in the CI and available in the
[registry](https://github.com/quarkslab/quokka/packages).

It should be possible to install directly from PIP using this kind of commmand:

```commandline
$ pip install quokka-project
```

### IDA Plugin

Note: The IDA plugin is not needed to read a `Quokka` generated file. It is
only used to generate them.

The plugin is built on the CI and available in the
[Release](https://github.com/quarkslab/quokka/releases).

To download the plugin, get the file named `quokka_plugin**.so`.

## Usage

### Export a file

!!! note

    This requires a working IDA installation.


- Either using command line:
```commandline
$ idat64 -OQuokkaAuto:true -A /path/to/hello.i64
```

Note: We are using `idat64` and not `ida64` to increase the export speed
because we don't need the graphical interface.

- Using the plugin shortcut inside IDA: (by default) Alt+A

### Load an export file

```python
import quokka

# Directly from the binary (requires the IDA plugin to be installed)
ls = quokka.Program.from_binary("/bin/ls")

# From the exported file
ls = quokka.Program("ls.quokka",  # the exported file 
                    "/bin/ls")    # the original binary
```

## Building

### Build

```console
user@host:~/quokka$ cmake -B build \ # Where to build 
                          -S . \ # Where are the sources
                          -DIdaSdk_ROOT_DIR:STRING=path/to/ida_sdk \ # Path to IDA SDK 
                          -DIda_BIN_DIR:STRING=/path/to/ida/dir \ # Path to IDA 
                          -DCMAKE_BUILD_TYPE:STRING=Release \ # Build Type 
                          -DBUILD_TEST:BOOL=OFF # Don't build the tests

user@host:~/quokka$ cmake --build build --target quokka_plugin -- -j
```

To install the plugin:

```console
user@host:~/quokka$ cmake --install build
```

In any case, the plugin will also be in `build/quokka-install`. You can
copy it to Ida plugin directory.

```console
user@host:~/quokka$ cp build/quokka-install/quokka*64.so $IDA_BIN_DIR/plugins/
```

For more detailed information about building, see [Building](installation.md#ida-plugin)