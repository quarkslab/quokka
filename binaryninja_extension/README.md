

This project checks in the generated quokka_pb2.py file to
comply with the simpler workflow for github hosted workflows.

## Headless Export

Headlessly using the BinaryNinja API requires a commercial license currently.
The UI plugin can still be used to export .quokka files. 

Use `export_headless.py` with a Python environment that can import the Binary Ninja
Python API:

```bash
python binaryninja_extension/export_headless.py /path/to/binary --out /tmp/output.quokka --mode LIGHT
```

The output path defaults to `<input>.quokka`. 
