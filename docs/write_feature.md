# Editing a Program

**Quokka** enables editing some fields and propagating those changes back to disassembler
in an asynchronous manner. You can rename functions, set their prototype, or add comments
directly on the Python objects. Changes applied back to the disassembler database can be
propagated back in the quokka file by re-exporting the binary after committing the changes.

This workflow is useful when you want to share analysis results with
colleagues, feed them into another tool, or permanently record findings in the
IDA or Ghidra project.

## Modifying function metadata

### Renaming a function

Assign a new value to `Function.name`:

```python
import quokka

prog = quokka.Program("binary.quokka", "binary")

func = prog.get_function("sub_401234")
func.name = "authenticate_user"
```

### Setting a function prototype

Assign a C-style prototype string to `Function.prototype`:

```python
func.prototype = "int authenticate_user(const char *user, const char *password)"
```

### Adding a comment

Call `Function.add_comment` to append a comment to a function:

```python
func.add_comment("Entry point for the authentication logic.")
```

## Adding new types

You can inject new type definitions (structs, enums, unions, typedefs) into
the program. These are recorded as `is_new=True` in the protobuf and applied
back to the disassembler database via `commit()`.

```python
# Add types from C declaration strings
prog.add_type("struct context { int id; char name[64]; };")
prog.add_type("enum status { OK=0, ERROR=1 };")
prog.add_type("typedef unsigned int uint32;")
```

See the [Types](types.md#adding-new-types) page for the full API and more
examples.

## Persisting changes

Three methods control how modifications are saved.

### `write` -- save to the `.quokka` file only

`Program.write` serialises the modified protobuf back to disk. It does **not**
interact with any disassembler. Use it when you want to snapshot the current
annotations or share them without modifying the disassembler database.

```python
# Overwrite the original file
prog.write()

# Or save to a new file
prog.write("binary_annotated.quokka")
```

### `commit` -- apply changes to the disassembler database

`Program.commit` calls `write()` and then spawns the matching headless
disassembler to apply recorded edits back to the database/project.
The full function signature (name, return type, parameter types, parameter
names, and parameter count) is applied to the disassembler database.

```python
# IDA: database_file is the .i64 to modify
errors = prog.commit(database_file="binary.i64", overwrite=True)

# Ghidra: database_file is a .gpr file or a project directory
errors = prog.commit(database_file="binary_ghidra/binary.gpr", overwrite=True)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `database_file` | `Path\|str\|None` | backend default | IDA `.i64` database, Ghidra `.gpr` file, or Ghidra project directory |
| `disassembler_path` | `Path\|str\|None` | `None` | Installation directory of the disassembler recorded in the `.quokka` file (IDA install dir, or Ghidra install dir / `GHIDRA_INSTALL_DIR`) |
| `overwrite` | `bool` | `True` | Allow modifying an existing database/project. Raises `FileExistsError` when `False` and it exists. Logs a warning when `True`. |
| `timeout` | `int` | `600` | Maximum seconds to wait for the disassembler |

Returns the number of errors (0 = all edits applied successfully).

!!! note
    `commit` requires the corresponding disassembler integration: IDA with the
    Quokka plugin, or Ghidra with the QuokkaExporter extension.

### `regenerate` -- commit then re-export

`Program.regenerate` calls `commit()` and immediately re-exports the binary,
returning a fresh `Program` instance that reflects the updated disassembler
database. This is the right choice when you want a clean `.quokka` file that
incorporates your annotations as first-class exported data.

```python
updated_prog = prog.regenerate(database_file="binary.i64", overwrite=True)
```

It accepts the same parameters as `commit`.

## Full example

```python
import quokka

# Load an existing export
prog = quokka.Program("binary.quokka", "binary")

# Locate a function by its auto-generated name
func = prog.get_function("sub_401234")

# Annotate it
func.name = "authenticate_user"
func.prototype = "int authenticate_user(const char *user, const char *password)"
func.add_comment("Validates credentials against the internal user table.")

# Write to the .quokka file and push changes to the IDA database
prog.commit(database_file="binary.i64", overwrite=True)
```

## From the command line (`quokka-apply`)

The `quokka-apply` CLI applies edits stored in a `.quokka` file back to the
disassembler database/project without writing Python code:

```commandline
$ quokka-apply binary.quokka binary --overwrite
$ quokka-apply binary.quokka binary --regenerate --overwrite
$ quokka-apply binary.quokka binary --database-file binary_ghidra/binary.gpr --disassembler-path "$GHIDRA_INSTALL_DIR" --overwrite
```

| Option | Description |
|--------|-------------|
| `--commit` | Write `.quokka` and apply edits to the disassembler (default) |
| `--regenerate` | Commit then re-export a fresh `.quokka` from the disassembler |
| `--database-file` | IDA `.i64` database or Ghidra `.gpr`/project directory |
| `--disassembler-path` | Disassembler installation directory (IDA or Ghidra, per the backend recorded in the `.quokka`) |
| `--overwrite` | Allow overwriting an existing disassembler database |
| `-v`, `--verbose` | Increase logging verbosity |

## From IDA

If you are already running inside IDA (e.g. via IDAPython), you can apply
edits directly without spawning a new instance:

```python
from quokka import Program
from quokka.backends.ida import apply_quokka

p = Program("binary.quokka", "binary")
errors = apply_quokka(p)
```

## Summary

| Method | Writes `.quokka` file | Applies to disassembler database | Returns fresh `Program` |
|---|:---:|:---:|:---:|
| `prog.write()` | Yes | No | No |
| `prog.commit(database_file=...)` | Yes | Yes (IDA/Ghidra) | No |
| `prog.regenerate(database_file=...)` | Yes | Yes (IDA/Ghidra) | Yes |
