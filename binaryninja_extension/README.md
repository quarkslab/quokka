# Quokka BinaryNinja Extension

## Protobuf generation

The protobuf support module `bn_quokka/quokka_pb2.py` is generated from the
shared schema `proto/quokka.proto` at the repository root and is not checked
in, following the same convention as the Python bindings. Generate it with:

```bash
pip install -r binaryninja_extension/requirements.txt
python binaryninja_extension/generate_proto.py
```

The pinned grpcio-tools version keeps the generated code on the same protobuf
release line used by the other exporters (see requirements.txt).

`install_dev.py` runs the generation automatically before symlinking the
extension into the BinaryNinja user plugin directory, and the test suite
generates the file on demand when grpcio-tools is available.

## Headless Export

Headlessly using the BinaryNinja API requires a commercial license currently.
The UI plugin can still be used to export .quokka files.

Use `export_headless.py` with a Python environment that can import the Binary Ninja
Python API:

```bash
python binaryninja_extension/export_headless.py /path/to/binary --out /tmp/output.quokka --mode LIGHT
```

The output path defaults to `<input>.quokka`.
