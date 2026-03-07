# Types

**Quokka** exports the type information recorded by IDA (structures, unions,
enumerations, arrays and pointers) and exposes it through a hierarchy of Python
objects. These objects are useful for understanding data layout, reconstructing
high-level semantics, and cross-referencing types with the data or code that
uses them.

## Type hierarchy

```
CoreType                         ← abstract base for every type
├── BaseType          (IntEnum)  ← primitive (char, int, float, …)
├── ComplexType                  ← abstract base for named types
│   ├── EnumType                 ← C enum
│   ├── StructureType  (dict)    ← C struct
│   │   └── UnionType            ← C union (subclass of StructureType)
│   ├── ArrayType                ← C array (T[N])
│   └── PointerType              ← C pointer (T*)
├── EnumTypeMember               ← one value inside an EnumType
└── StructureTypeMember          ← one field inside a StructureType/UnionType
```

Every type object exposes a set of `is_*` boolean properties so you can check
its kind without `isinstance` calls:

| Property | True for |
|---|---|
| `is_base_type` | `BaseType` |
| `is_enum` | `EnumType` |
| `is_struct` | `StructureType` |
| `is_union` | `UnionType` |
| `is_array` | `ArrayType` |
| `is_pointer` | `PointerType` |
| `is_composite` | Any `ComplexType` (enum, struct, union, array, pointer) |
| `is_member` | `StructureTypeMember` or `EnumTypeMember` |

## Accessing types from a Program

```python
import quokka

prog = quokka.Program("binary.quokka", "binary")

# Iterate over every exported type
for t in prog.types:
    print(type(t).__name__, getattr(t, "name", t))

# Only structures
for struct in prog.structures:
    print(struct.name, struct.size, "bytes")

# Only enumerations
for enum in prog.enums:
    print(enum.name)
```

## BaseType — primitives

`BaseType` is an `IntEnum` that represents the primitive C types IDA knows
about:

| Name | C equivalent | Size (bytes) |
|---|---|---|
| `BYTE` | `char` | 1 |
| `WORD` | `short` | 2 |
| `DOUBLE_WORD` | `int` | 4 |
| `QUAD_WORD` | `int64_t` | 8 |
| `OCTO_WORD` | `int128_t` | 16 |
| `FLOAT` | `float` | 4 |
| `DOUBLE` | `double` | 8 |
| `VOID` | `void` | 0 |
| `UNKNOWN` | — | 0 |

```python
from quokka.data_type import BaseType

bt = BaseType.DOUBLE_WORD
print(bt.size)   # 4
print(bt.c_str)  # <T:int>
print(bt.is_base_type)  # True
```

## StructureType — C structs

`StructureType` behaves like a `dict` keyed by **positional index** (integer,
starting at 0). Each value is a `StructureTypeMember`.

### Key attributes

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Structure name as defined in IDA |
| `size` | `int` | Total size in bytes (0 if variable-length) |
| `c_str` | `str` | C declaration of the structure |
| `comments` | `list[str]` | Analyst comments |
| `members` | `list[StructureTypeMember]` | Members in declaration order |

```python
for struct in prog.structures:
    print(f"struct {struct.name} ({struct.size} bytes)")
    for member in struct.members:
        byte_offset = member.offset // 8
        byte_size   = member.size   // 8
        print(f"  +0x{byte_offset:02x}  {member.name}  ({byte_size} bytes)  type={member.type}")
```

!!! note "Offsets and sizes are in bits"
    `StructureTypeMember.offset` and `StructureTypeMember.size` are expressed
    in **bits**, not bytes. Divide by 8 to get byte values. This representation
    is necessary to support bit-fields.

### StructureTypeMember

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Field name |
| `offset` | `int` | Bit offset within the parent structure |
| `size` | `int` | Size in bits (0 for variable-length fields) |
| `type` | `TypeT` | Resolved type of the field |
| `parent` | `StructureType` | Back-reference to the containing structure |
| `comments` | `list[str]` | Analyst comments |
| `data_refs_to` | `list[AddressT]` | Addresses that reference this field |

```python
struct = next(prog.structures)
first_member = struct.members[0]
print(first_member.name)           # e.g. "next"
print(first_member.offset // 8)   # byte offset
print(first_member.type)           # e.g. <TPtr: next->...>
```

## UnionType — C unions

`UnionType` is a subclass of `StructureType`. It works identically except that
all members conceptually share offset 0 (all variants overlay the same memory).
The dict is still keyed by **positional index** to avoid collisions.

```python
for t in prog.types:
    if t.is_union:
        print(f"union {t.name} ({t.size} bytes)")
        for member in t.members:
            print(f"  variant {member.name}: {member.type}")
```

## EnumType — C enumerations

### Key attributes

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Enum name |
| `size` | `int` | Storage size in bytes (derived from `base_type`) |
| `base_type` | `BaseType` | Underlying integer type |
| `members` | `Iterable[EnumTypeMember]` | All enum values |
| `c_str` | `str` | C declaration |
| `comments` | `list[str]` | Analyst comments |

`EnumType` is **iterable** and **subscriptable by positional index**. Members
can also be accessed as **attributes** using their name:

```python
for enum in prog.enums:
    print(f"enum {enum.name} (base: {enum.base_type})")

    # Iterate
    for member in enum:
        print(f"  {member.name} = {member.value}")

    # Positional access
    first = enum[0]

    # Attribute access by name
    val = enum.SOME_VALUE  # equivalent to enum["SOME_VALUE"]
```

### EnumTypeMember

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Constant name |
| `value` | `int` | Integer value |
| `size` | `int` | Same as the parent enum's size |
| `base_type` | `BaseType` | Underlying integer type |
| `parent` | `EnumType` | Back-reference to the containing enum |
| `comments` | `list[str]` | Analyst comments |
| `data_refs_to` | `list[Data]` | Data objects that reference this constant |

## ArrayType — C arrays

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Type name |
| `size` | `int` | Total size in bytes |
| `element_type` | `TypeT` | Type of each element |
| `array_size` | `int` | Number of elements |
| `c_str` | `str` | C declaration |

```python
for t in prog.types:
    if t.is_array:
        print(f"{t.name}: {t.element_type}[{t.array_size}]  ({t.size} bytes)")
```

## PointerType — C pointers

| Attribute | Type | Description |
|---|---|---|
| `name` | `str` | Type name |
| `size` | `int` | Pointer size in bytes (4 or 8 depending on architecture) |
| `pointed_type` | `TypeT` | The type being pointed to |
| `c_str` | `str` | C declaration |

```python
for t in prog.types:
    if t.is_pointer:
        print(f"{t.name} → {t.pointed_type}  (size={t.size})")
```

## Adding new types

You can define new types from Python and persist them back to the
disassembler database. New types are created via `Program.add_type()` and
are marked with `is_new=True` so the backend knows to register them.

### From a C declaration string

```python
# Struct
prog.add_type(c_str="struct point { int x; int y; };")

# Enum
prog.add_type(c_str="enum color { RED=0, GREEN=1, BLUE=2 };")

# Typedef
prog.add_type(c_str="typedef unsigned int uint32;")

# Union
prog.add_type(c_str="union data { int i; float f; };")
```

### From an existing type object

```python
from quokka.quokka_pb2 import Quokka as Pb
from quokka.data_type import StructureType

ct = Pb.CompositeType()
ct.name = "my_struct"
ct.type = Pb.CompositeType.TYPE_STRUCT
ct.c_str = "struct my_struct { int a; int b; };"

struct = StructureType(0, ct, prog, is_new=True)
prog.add_type(type_obj=struct)
```

### Persisting new types

New types are appended to the protobuf `types` array, so `prog.write()` and
`prog.commit()` automatically include them. When applied back to IDA, the
backend reconstructs each new type from its `c_str` field using
`parse_decls()`.

```python
# Save to .quokka only
prog.write()

# Or apply to IDA and re-export
prog.commit(database_file="binary.i64", overwrite=True)
```

!!! note
    Duplicate type names are rejected -- `add_type()` raises `QuokkaError`
    if a type with the same name already exists in the program.

## Cross-references from types

Complex types and their members carry cross-reference lists that tell you which
data objects use them:

```python
for struct in prog.structures:
    refs = struct.data_refs_to
    if refs:
        print(f"{struct.name} is referenced by {len(refs)} data object(s)")

    for member in struct.members:
        for addr in member.data_refs_to:
            print(f"  field {member.name} accessed from 0x{addr:x}")
```

The following cross-reference accessors are available on `ComplexType`:

| Property | Description |
|---|---|
| `data_refs_to` | All data cross-references to this type |
| `data_read_refs_to` | Read cross-references only |
| `data_write_refs_to` | Write cross-references only |

`EnumTypeMember` and `StructureTypeMember` also expose `data_refs_to`.

## Checking types with `is_*` properties

Because a `TypeT` can be any of the concrete type classes it is often cleaner
to use the boolean properties rather than `isinstance`:

```python
def describe(t) -> str:
    if t.is_base_type:
        return f"primitive {t.c_str}"
    elif t.is_struct:
        return f"struct {t.name} ({len(t.members)} fields)"
    elif t.is_union:
        return f"union {t.name} ({len(t.members)} variants)"
    elif t.is_enum:
        return f"enum {t.name} ({sum(1 for _ in t.members)} values)"
    elif t.is_array:
        return f"array {t.element_type}[{t.array_size}]"
    elif t.is_pointer:
        return f"pointer → {t.pointed_type}"
    return "unknown"

for t in prog.types:
    print(describe(t))
```
