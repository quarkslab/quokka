# Cross-References

Cross-references (*xrefs*) record every edge between objects in the binary:
which instruction calls which function, which instruction reads which global
variable, which data object holds a pointer to another, which instruction
accesses a specific struct field, and so on.

!!! warning
    On IDA Pro, xrefs are retrieve using disassembler engine (not decompiler).

Quokka organises xrefs into three orthogonal dimensions:

* **Kind**: code / data / type, what kind of relationship it is
* **Direction**:
    * *from*: refences originating from this object (e.g. instructions called by this function)
    * *to*: references pointing to this object (e.g. instructions calling this function)
* **Object addressed**:
    * *address*: most xrefs point to an address (e.g. instruction at 0x401000 calls 0x402000)
    * *type object*: reference to a type or a type member (`TypeReference`)

## Reference types (`RefType`)

Every xref carries a `RefType` that captures the precise nature of the
relationship:

| `RefType` | Category | Description |
|---|---|---|
| `JMP_UNCOND` | code | Unconditional direct jump |
| `JMP_COND` | code | Conditional direct jump |
| `JMP_INDIR` | code | Indirect jump (via pointer) |
| `CALL` | code | Direct function call |
| `CALL_INDIR` | code | Indirect call (call through register or table) |
| `DATA_READ` | data | Instruction reads a data object |
| `DATA_WRITE` | data | Instruction writes a data object |
| `DATA_INDIR` | data | Indirect data reference (pointer dereferencing) |
| `TYPE_SYMBOL` | type | *Unused!*                           |
| `UNKNOWN` | — | Unresolved reference type |

Four boolean helper properties are available on every `RefType` value:

```python
from quokka.types import RefType

RefType.CALL.is_code      # True  (jumps and calls)
RefType.CALL.is_call      # True  (calls only)
RefType.JMP_COND.is_code  # True
RefType.JMP_COND.is_call  # False
RefType.DATA_READ.is_data # True  (DATA_READ, DATA_WRITE, DATA_INDIR)
RefType.CALL_INDIR.is_dynamic # True  (JMP_INDIR, CALL_INDIR)
```

## The xref matrix

The table below summarises which combinations of source and destination objects
Quokka exports, and which `RefType` values can appear:

| From → / To ↓ | **Code** (instruction) | **Data** | **Type** |
|---|---|---|---|
| **Code** | `C`            | `D{I}`  | — |
| **Data** | `D{R,W,I}`     | `D{I}`  | — |
| **Type** | `D{I}`         | `D{R}`   | `D{R}`  |

Legend:

- `C` — code reference (one of the `JMP_*` / `CALL_*` ref types)
- `D` — data reference (`DATA_*` ref types)
- `{R}` / `{W}` / `{I}` — Read / Write / Indirect variant
- `—` — No possible xrefs

### Reading the matrix

- **Code→Code**: an instruction jumping or calling another address.  All five
  code `RefType` values can appear.
- **Code→Data**: an instruction that reads, writes, or indirectly accesses a
  data object.  Both direct (`DATA_READ`/`DATA_WRITE`) and indirect
  (`DATA_INDIR`) variants are exported.
- **Code→Type**: an instruction that references a type symbol (e.g. accessing a
  struct field at a known offset).  Only indirect (`DATA_INDIR`) references
  here.
- **Data→Code**: a data object containing a pointer to code (e.g. a function
  pointer in a vtable).  Only indirect references.
- **Data→Data**: a data object containing a pointer to another data object.
  Only indirect references.
- **Data→Type**: a data object whose type annotation points to a complex type
  or one of its members.  `(s)` means the target can be a `StructureTypeMember`
  instead of the type itself.
- **Type→Type**: one type referencing another type, or one of its members.
  `(s)` = struct/union member target, `(k)` = enum member target.

## Direction: *from* vs *to*

Every xref API property comes in two flavours:

| Suffix | You are asking… | Edge points… |
|---|---|---|
| `_from` | "what does **this object** reference?" | **out** of this object |
| `_to` | "what references **this object**?" | **in** to this object |

```
 [caller instruction]  --code_refs_from-->  [callee address]
 [callee instruction]  <--code_refs_to---   [caller address]
```

## API reference by object

### `Instruction`

```python
inst = func[block_addr][inst_addr]
```

| Property | Type | Description |
|---|---|---|
| `code_refs_from` | `list[AddressT]` | Code destinations of this instruction (jumps / calls) |
| `code_refs_to` | `list[AddressT]` | Addresses that jump or call to this instruction |
| `data_refs_from` | `list[Data \| Function \| AddressT]` | Data objects read/written by this instruction |
| `data_read_refs_from` | `list[Data \| Function \| AddressT]` | Read data refs from this instruction |
| `data_write_refs_from` | `list[Data \| Function \| AddressT]` | Write data refs from this instruction |
| `data_refs_to` | `list[Data \| Function \| AddressT]` | Data objects that point to this instruction |
| `data_read_refs_to` | `list[Data \| Function \| AddressT]` | Read data refs to this instruction |
| `data_write_refs_to` | `list[Data \| Function \| AddressT]` | Write data refs to this instruction |
| `type_refs_from` | `list[TypeReference]` | Type / struct member referenced by this instruction |
| `callees` | `list[AddressT]` | Functions called by this instruction (subset of `code_refs_from`) |
| `callers` | `list[AddressT]` | Callers of this instruction (subset of `code_refs_to`) |
| `is_call` | `bool` | True if this instruction performs a call |
| `is_jump` | `bool` | True if this instruction performs a jump |
| `is_conditional_jump` | `bool` | True if this instruction performs a conditional jump |
| `is_dynamic` | `bool` | True if the reference is indirect (call/jump through pointer) |

```python
for inst in func.instructions:
    if inst.is_call:
        print(f"0x{inst.address:x} calls {inst.code_refs_from}")
    for data in inst.data_read_refs_from:
        print(f"0x{inst.address:x} reads {data}")
    for t in inst.type_refs_from:
        print(f"0x{inst.address:x} accesses type {t}")
```

### `Operand`

Xrefs are also resolved at the individual operand level when the operand can be
unambiguously identified.

| Property | Type | Description |
|---|---|---|
| `data_refs_from` | `list[Data \| Function \| AddressT]` | Data object this operand references |
| `code_refs_from` | `list[AddressT]` | Code address this operand references |
| `type_refs_from` | `list[TypeReference]` | Type / member this operand references |

```python
for op in inst.operands:
    if op.data_refs_from:
        print(f"  operand {op} → data {op.data_refs_from}")
    if op.type_refs_from:
        print(f"  operand {op} → type {op.type_refs_from}")
```

### `Data`

```python
data = prog.data[addr]
```

| Property | Type | Description |
|---|---|---|
| `code_refs_to` | `list[AddressT]` | Instructions that reference this data object |
| `data_refs_to` | `list[Data \| Function \| AddressT]` | Data objects that point to this object |
| `data_read_refs_to` | `list[Data \| Function \| AddressT]` | Read references to this object |
| `data_write_refs_to` | `list[Data \| Function \| AddressT]` | Write references to this object |
| `data_refs_from` | `list[Data \| Function \| AddressT]` | Objects this data points to (pointer data) |
| `data_read_refs_from` | `list[Data \| Function \| AddressT]` | Targets this data reads from |
| `data_write_refs_from` | `list[Data \| Function \| AddressT]` | Targets this data writes to |
| `type_refs_from` | `list[TypeReference]` | Type or type member referenced by this data |
| `prev` | `Data \| None` | Data at the highest address below this one |
| `next` | `Data \| None` | Data at the lowest address above this one |

```python
# Find all instructions reading a global variable
data = prog.data[0x404080]
for addr in data.code_refs_to:
    print(f"instruction 0x{addr:x} references this data")

# Follow a pointer stored inside a data object
for target in data.data_refs_from:
    print(f"this data points to {target}")
```

### `Function`

`Function` provides call-graph level xrefs aggregated across all its
instructions.

| Property | Type | Description |
|---|---|---|
| `callers` | `list[Function]` | Functions that call this function |
| `callees` | `list[Function]` | Functions called by this function |

```python
for caller in func.callers:
    print(f"{caller.name} calls {func.name}")

for callee in func.callees:
    print(f"{func.name} calls {callee.name}")
```

### Complex types (`StructureType`, `UnionType`, `EnumType`, `ArrayType`, `PointerType`)

| Property | Type | Description |
|---|---|---|
| `data_refs_to` | `list[Data]` | Data objects that use (are annotated with) this type |
| `data_read_refs_to` | `list[Data]` | Read-only data references to this type |
| `data_write_refs_to` | `list[Data]` | Write data references to this type |

### `StructureTypeMember` / `EnumTypeMember`

| Property | Type | Description |
|---|---|---|
| `data_refs_to` | `list[Data \| AddressT]` | Data objects or addresses that access this specific member |

```python
for struct in prog.structures:
    for member in struct.members:
        refs = member.data_refs_to
        if refs:
            print(f"{struct.name}.{member.name} accessed from {len(refs)} location(s)")
```

## Common patterns

### Find all call sites of a function

```python
func = prog.get_function("authenticate_user")
for caller in func.callers:
    print(f"called from {caller.name}")
```

### Trace all reads of a global variable

```python
data = prog.data[0x404080]
for addr in data.code_refs_to:
    print(f"0x{addr:x}")
```

### List all struct fields accessed by a function

```python
import quokka

prog = quokka.Program("binary.quokka", "binary")
func = prog.get_function("sub_401234")

accessed = set()
for inst in func.instructions:
    for t in inst.type_refs_from:
        if t.is_member:
            accessed.add((t.parent.name, t.name))

for struct_name, field_name in sorted(accessed):
    print(f"{struct_name}.{field_name}")
```

### Find data objects whose type is a given structure

```python
target_struct = next(s for s in prog.structures if s.name == "FILE")
for data in target_struct.data_refs_to:
    print(f"0x{data.address:x}  {data}")
```

### Detect indirect calls

```python
for func in prog.values():
    for inst in func.instructions:
        if inst.is_call and inst.is_dynamic:
            print(f"0x{inst.address:x}  indirect call in {func.name}")
```
