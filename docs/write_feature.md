# Editing a Program

**Quokka** enables editing some fields and propagating those changes back to disassembler
in an asynchronous manner. You can rename functions, set their prototype, or add comments
directly on the Python objects. Changes applied back to the disassembler database can be
propagated back in the quokka file by re-exporting the binary after committing the changes.

This workflow is useful when you want to share analysis results with
colleagues, feed them into another tool, or permanently record findings in the
IDA project.

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

## Persisting changes

Three methods control how modifications are saved.

### `write` — save to the `.quokka` file only

`Program.write` serialises the modified protobuf back to disk. It does **not**
interact with IDA. Use it when you want to snapshot the current annotations or
share them without modifying the IDA database.

```python
# Overwrite the original file
prog.write()

# Or save to a new file
prog.write("binary_annotated.quokka")
```

### `commit` — apply changes to IDA

`Program.commit` calls `write()` and then opens IDA headlessly to apply all
recorded edits (names, prototypes, comments) to the IDA database (`.i64`).

```python
prog.commit()
```

!!! note
    `commit` requires a working IDA installation with the Quokka plugin. The
    function returns `True` when the edits were applied successfully (or with
    non-fatal errors) and raises `QuokkaError` on a hard failure.

### `regenerate` — commit then re-export

`Program.regenerate` calls `commit()` and immediately re-exports the binary,
returning a fresh `Program` instance that reflects the updated IDA database.
This is the right choice when you want a clean `.quokka` file that incorporates
your annotations as first-class exported data.

```python
updated_prog = prog.regenerate()
```

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
prog.commit()
```

## From IDA

You can also applies edits from IDA with the following workflow:

```python
from quokka import Program

# Import IDA specific Python code to import a Quokka file
from quokka.backends.ida import apply_quokka

p = Program("binary.quokka", "binary")
apply_quokka(p)
```

## Summary

| Method | Writes `.quokka` file | Applies to IDA database | Returns fresh `Program` |
|---|:---:|:---:|:---:|
| `prog.write()` | Yes | No | No |
| `prog.commit()` | Yes | Yes | No |
| `prog.regenerate()` | Yes | Yes | Yes |
