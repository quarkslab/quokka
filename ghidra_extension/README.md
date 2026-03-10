# Quokka Ghidra Extension

Ghidra extension that exports analysis to `.quokka` protobuf files, consumable by the [quokka Python library](https://pypi.org/project/quokka-project/).

## Requirements

- JDK 21+
- Ghidra >= 12.0.3 (the `third_party/ghidra` submodule tag is the source of truth for the tested version)

A Gradle wrapper (>= 8.5) is included -- no system-wide Gradle install is needed.

## Build

`GHIDRA_INSTALL_DIR` must point to a Ghidra installation. You can use the helper script to fetch the matching release:

```bash
export GHIDRA_INSTALL_DIR="$(scripts/fetch_ghidra.sh)"
cd ghidra_extension
rm -rf dist/
./gradlew buildExtension
```

The extension ZIP is generated in `dist/`.

## Install

Copy the generated ZIP from `dist/` into Ghidra:

1. Open Ghidra
2. File > Install Extensions
3. Add the ZIP file
4. Restart Ghidra

Or install from the command line:

```bash
unzip -o dist/ghidra_*_QuokkaExporter.zip -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

## Usage

### GUI

1. Open a binary in Ghidra's CodeBrowser
2. File > Export Program
3. Select "Quokka" format
4. Choose output file
5. Click Export

### Headless (CLI)

The recommended way to run a headless export is through `quokka-cli`:

```bash
quokka-cli --backend ghidra /path/to/binary -o /tmp/output.quokka
```

Or via the Python API:

```python
import quokka
p = quokka.Program.from_binary("/path/to/binary", disassembler=quokka.Disassembler.GHIDRA)
```

Both require `GHIDRA_INSTALL_DIR` to be set and the extension installed.

### Headless (Advanced)

For more fine-grained control over the Ghidra analysis pipeline, you can invoke `analyzeHeadless` directly. The extension **must be installed** into the Ghidra directory for this to work (Ghidra's OSGI classloader does not pick up external JARs for script dependencies).

```bash
export GHIDRA_INSTALL_DIR="$(scripts/fetch_ghidra.sh)"

"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /tmp/proj Test \
  -import /path/to/binary \
  -scriptPath ghidra_extension/src/script/ghidra_scripts \
  -postScript QuokkaExportHeadless.java "--out=/tmp/output.quokka" "--mode=LIGHT"
```

### Verify

```bash
python -c "
import quokka
p = quokka.Program('/tmp/output.quokka', '/path/to/binary')
print(f'Functions: {len(p.fun_names)}')
print(f'Segments: {len(p.proto.segments)}')
"
```

## Export Modes

- **LIGHT** (default): Blocks carry `size` and `n_instr`. Instructions decoded at load time via Capstone.
- **SELF_CONTAINED**: Not yet implemented. Will include full instruction data in the export.

## Testing

```bash
export GHIDRA_INSTALL_DIR="$(scripts/fetch_ghidra.sh)"
cd ghidra_extension
./gradlew test
```

## Project Structure

```
ghidra_extension/
  src/
    main/java/com/quarkslab/quokka/
      QuokkaExporter.java          # GUI entry point (File > Export > Quokka)
      ExportContext.java            # Shared export state
      ExportPipeline.java          # Phase orchestrator
      export/                      # One class per export phase
      util/                        # Mapper and utility classes
      compat/                      # Ghidra version compatibility
    main/proto/
      quokka.proto -> ../../proto/ # Symlink to shared schema
    test/java/                     # JUnit tests
    script/ghidra_scripts/
      QuokkaExportHeadless.java    # Headless export script
```
