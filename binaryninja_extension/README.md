# Quokka BinaryNinja Extension

## Protobuf module

`bn_quokka/quokka_pb2.py` is generated from the shared schema
`proto/quokka.proto` at the repository root, using the grpcio-tools version
pinned in `requirements.txt` (which keeps the generated code on the same
protobuf release line as the other exporters).

Unlike the Python bindings, which generate the module at wheel build time,
the generated module is committed here: a BinaryNinja plugin is distributed
as a plain git tree, so there is no build or install step where generation
could run on the user's machine. End users therefore only need the protobuf
runtime declared in `plugin.json`. CI regenerates the module with the pinned
toolchain and fails if the committed copy is stale.

After changing `proto/quokka.proto`, regenerate it with:

```bash
pip install -r binaryninja_extension/requirements.txt
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
