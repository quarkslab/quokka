# Decompilation

**Quokka** can optionally embed the Hex-Rays pseudocode for each function
directly inside the exported `.quokka` file. This lets you work with
high-level C-like code in your analysis scripts without keeping an IDA session
open.

!!! note
    Decompilation export is currently supported only with the **IDA backend**
    and requires a Hex-Rays decompiler licence for the target architecture.
    The Ghidra extension does not yet export decompiled code.
    The export will succeed even when the decompiler is unavailable; in that
    case `Program.decompiled_activated` is `False` and
    `Function.decompiled_code` is an empty string for every function.

## Enabling decompilation at export time

=== "IDA command line"

    Pass `-OQuokkaDecompiled:true` alongside the other options:

    ```commandline
    idat64 -OQuokkaAuto:true -OQuokkaDecompiled:true -A /path/to/binary.i64
    ```

=== "IDA GUI"

    Toggle the **Export decompiled code** checkbox in the Quokka export
    dialog (shortcut: **Alt+A** by default).

=== "quokka-cli"

    Add the `--decompiled` flag:

    ```commandline
    quokka-cli --decompiled /path/to/binary
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
