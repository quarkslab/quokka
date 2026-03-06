# Quokka Ghidra Extension

Ghidra extension that exports analysis to `.quokka` protobuf files, consumable by the [quokka Python library](https://pypi.org/project/quokka-project/).

## Requirements

- JDK 21+
- Gradle >= 8.5
- Ghidra >= 12.0.3

## Build

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3
cd ghidra_extension
gradle build
```

The distributable ZIP is generated in `dist/`.

## Install

Copy the generated ZIP from `dist/` into Ghidra:

1. Open Ghidra
2. File > Install Extensions
3. Add the ZIP file
4. Restart Ghidra

## Usage

### GUI

1. Open a binary in Ghidra's CodeBrowser
2. File > Export Program
3. Select "Quokka" format
4. Choose output file
5. Click Export

### Headless

```bash
analyzeHeadless /tmp/proj Test \
  -import /path/to/binary \
  -scriptPath ghidra_extension/src/script/ghidra_scripts \
  -postScript QuokkaExportHeadless.java \
  --out=/tmp/output.quokka --mode=LIGHT
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
gradle test
```

## Project Structure

```
ghidra_extension/
  src/
    main/java/com/quarkslab/quokka/
      QuokkaExporter.java          # GUI entry point
      ExportContext.java            # Shared export state
      ExportPipeline.java          # Phase orchestrator
      export/                      # One class per export phase
      util/                        # Mapper and utility classes
      compat/                      # Version compatibility
    main/proto/
      quokka.proto -> ../../proto/ # Symlink to shared schema
    test/java/                     # JUnit tests
    script/ghidra_scripts/
      QuokkaExportHeadless.java    # Headless export script
```
