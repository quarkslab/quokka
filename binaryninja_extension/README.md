# Quokka BinaryNinja Extension

## Distribution

The extension is installed manually: symlink or copy this directory into the
Binary Ninja user plugin folder (`install_dev.py` automates the symlink). It
cannot be listed in the official plugin manager from this repository, because
the plugin manager requires `plugin.json` at the root of the repository it
fetches; publishing a dedicated distribution repository would lift that
limitation.

`plugin.json` declares Binary Ninja 4.0 (build 4911) as the minimum version:
all APIs used are available there and the protobuf>=6.31 runtime requires the
Python >= 3.9 bundled with modern builds. Development and testing happen
against current stable releases.

## Code layout

```
bn_quokka/
├── export.py        # public API: pipeline orchestration and entry points
├── context.py       # ExportContext state shared by all pipeline phases
├── util.py          # BinaryNinja primitives: segments, addresses, type mapping
├── quokka_pb2.py    # generated protobuf module (see below)
└── exporters/       # one module per semantic cluster of the schema
    ├── binary.py        # program image: metadata, segments, layout, data items
    ├── types.py         # type table and C header collection
    ├── cfg.py           # functions, basic blocks, and edges
    ├── instructions.py  # instruction/operand encoding from disassembly tokens
    └── references.py    # cross-references between code and data
```

`bn_quokka.export` is the stable import surface; everything the plugin, the
headless CLI, and external scripts need is importable from there.

## Protobuf module

`bn_quokka/quokka_pb2.py` is generated from the shared schema
`proto/quokka.proto` at the repository root, using the grpcio-tools version
pinned in `requirements-dev.txt` (which keeps the generated code on the same
protobuf release line as the other exporters).

Unlike the Python bindings, which generate the module at wheel build time,
the generated module is committed here: a BinaryNinja plugin is distributed
as a plain git tree, so there is no build or install step where generation
could run on the user's machine. End users therefore only need the protobuf
runtime declared in `plugin.json`. CI regenerates the module with the pinned
toolchain and fails if the committed copy is stale.

After changing `proto/quokka.proto`, regenerate it with:

```bash
pip install -r binaryninja_extension/requirements-dev.txt
python binaryninja_extension/generate_proto.py
```

`install_dev.py` also runs the generation automatically before symlinking the
extension into the BinaryNinja user plugin directory.

## Headless Export

Headlessly using the BinaryNinja API requires a commercial license currently.
The UI plugin can still be used to export .quokka files.

Use `export_headless.py` with a Python environment that can import the Binary Ninja
Python API:

```bash
python binaryninja_extension/export_headless.py /path/to/binary --out /tmp/output.quokka --mode LIGHT
```

The output path defaults to `<input>.quokka`.
