# Decompilation

**Quokka** can optionally embed pseudocode for each function
directly inside the exported `.quokka` file. This lets you work with
high-level C-like code in your analysis scripts without keeping an IDA session
open.

!!! note
    IDA exports use Hex-Rays and require a decompiler licence for the target
    architecture. Ghidra exports use Ghidra's built-in decompiler when the
    extension is invoked with decompilation enabled. The export will succeed
    even when the decompiler is unavailable; in that case
    `Program.decompiled_activated` is `False` and
    `Function.decompiled_code` is an empty string for every function.

## Enabling decompilation at export time

=== "IDA command line"

    Pass `-OQuokkaDecompiled:true` alongside the other options:

    ```commandline
    idat -OQuokkaAuto:true -OQuokkaDecompiled:true -A /path/to/binary.i64
    ```

=== "IDA GUI"

    Toggle the **Export decompiled code** checkbox in the Quokka export
    dialog (shortcut: **Alt+A** by default).

=== "quokka-cli"

    Add the `--decompiled` flag:

    ```commandline
    quokka-cli --decompiled /path/to/binary
    ```

=== "Ghidra headless"

    Pass `--decompiled=true` to the Quokka headless script:

    ```commandline
    analyzeHeadless /tmp/proj Test \
      -process binary \
      -readOnly \
      -noanalysis \
      -scriptPath "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/QuokkaExporter/ghidra_scripts" \
      -postScript QuokkaExportHeadless.java \
      "--out=/tmp/binary.full.quokka" \
      "--mode=SELF_CONTAINED" \
      "--decompiled=true"
    ```

=== "Python API"

    Use `Program.from_binary` or `Program.generate` with `decompiled=True`:

    ```python
    import quokka

    prog = quokka.Program.from_binary(
        exec_path="binary",
        decompiled=True,
    )
    ```

## Reading decompiled code

After loading a `.quokka` file, check `Program.decompiled_activated` before
accessing pseudocode — it tells you whether decompilation was enabled when the
file was created.

Each `Function` exposes the pseudocode as the `decompiled_code` attribute (a
plain `str`). The attribute is an empty string when no pseudocode is available
for that function (e.g. library stubs or imported functions).

```python
import quokka

prog = quokka.Program("binary.quokka", "binary")

if not prog.decompiled_activated:
    print("File was exported without decompilation support.")
else:
    for func in prog.values():
        if func.decompiled_code:
            print(f"=== {func.name} (0x{func.start:x}) ===")
            print(func.decompiled_code)
            print()
```

### Checking a single function

```python
func = prog.get_function("authenticate_user")

if func.decompiled_code:
    print(func.decompiled_code)
else:
    print("No pseudocode available for this function.")
```

You can also address a function by entry address:

```python
func = prog[0x401234]
print(func.name)
print(func.decompiled_code)
```

## Naming a Function from Decompiled Code

The decompiled text is often enough to brainstorm and apply a better name
without returning to the disassembler:

```python
func = prog.get_function("FUN_10003e508")
print(func.decompiled_code)

func.name = "releaseSandboxExtensionHandleVector"
func.add_comment(
    "Releases sandbox extension handles and frees paired path storage."
)

# Persist the edit snapshot and apply it back to the disassembler project.
prog.commit(database_file="binary_ghidra/binary.gpr", overwrite=True)
```

`Program.write(...)` serializes the modified export. `Program.commit(...)`
applies edits back to the originating IDA database or Ghidra project.

## Use-case: searching pseudocode for patterns

Because `decompiled_code` is a plain string you can apply any text-processing
technique directly:

```python
import quokka

prog = quokka.Program("binary.quokka", "binary")

# Find all functions whose pseudocode mentions strcpy
vulnerable = [
    func for func in prog.values()
    if "strcpy" in func.decompiled_code
]

for func in vulnerable:
    print(f"0x{func.start:x}  {func.name}")
```
