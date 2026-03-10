# Instructions & Operands

Instructions are the lowest level of the Quokka object model. This page covers the `Instruction` and `Operand` objects, their attributes, and common instruction-level analysis patterns.

## The `Instruction` Object

```python
func = prog.get_function("main", approximative=False)
entry = func.get_block(func.start)

# Iterate instructions in a block
for addr, inst in entry.items():
    print(inst)

# Get by address — from a function or from the program
inst = func.get_instruction(0x401234)
inst = prog.get_instruction(0x401234)
```

## Instruction Attributes

```python
inst = func.get_instruction(0x401234)

inst.address    # 0x401234 (virtual address)
inst.size       # 3 (bytes)
inst.mnemonic   # "mov"
inst.cs_inst    # Capstone CsInsn object (full disassembly)

# Capstone gives full detail:
cs = inst.cs_inst
print(f"{cs.mnemonic} {cs.op_str}")  # "mov rax, qword ptr [rbx]"
print(f"groups: {cs.groups}")         # instruction groups
```

## Export Mode Impact

In **LIGHT mode**, only block start addresses are stored in the `.quokka` file. Capstone decodes instructions from the binary bytes at runtime. In **FULL mode**, mnemonics and operands are stored directly in the file — the binary is not needed at analysis time.

Either way, the Python API is identical:

```python
inst.mnemonic   # works in both modes
inst.cs_inst    # works in both modes (Capstone is always used)

# To check the current mode:
prog.mode   # ExporterMode.LIGHT or ExporterMode.FULL
```

## Operands

```python
from quokka.types import OperandType

inst = func.get_instruction(0x401234)
print(inst.operands)   # list of Operand objects

for op in inst.operands:
    if op.type == OperandType.REGISTER:
        print(f"  register: {op.register}")
    elif op.type == OperandType.IMMEDIATE:
        print(f"  value: {op.value:#x}")
    elif op.type == OperandType.MEMORY:
        print(f"  memory reference")
```

### Operand Types

| Type | Meaning | Example |
|------|---------|---------|
| `REGISTER` | CPU register | `rax`, `rbx`, `r8` |
| `IMMEDIATE` | Constant value | `0x42`, `-1`, `3.14` |
| `MEMORY` | Memory reference | `[rbp-8]`, `[rip+0x10]` |
| `OTHER` | Anything else | FPU stack, implicit operands |

```python
# Filter operands by type
imm_ops = [op for op in inst.operands
           if op.type == OperandType.IMMEDIATE]
reg_ops = [op for op in inst.operands
           if op.type == OperandType.REGISTER]
```

## String References

An instruction can reference string literals in the binary:

```python
inst = func.get_instruction(0x401250)

for s in inst.strings:
    print(f"String ref: {repr(s)}")
# String ref: 'Error: invalid argument\n'
```

## Call Targets

For call instructions, `call_target` resolves the callee. It raises
`FunctionMissingError` if the target cannot be resolved (e.g. indirect calls):

```python
from quokka.exc import FunctionMissingError

call_inst = func.get_instruction(0x4012a0)

try:
    target = call_inst.call_target
    print(f"Calls: {target.name}")
except FunctionMissingError:
    print("Indirect call (function pointer)")
```

## Register Access Mode

In FULL export mode, register read/write information is available:

```python
from quokka.types import AccessMode

for op in inst.operands:
    if op.type == OperandType.REGISTER:
        if AccessMode.READ in op.access:
            print(f"  reads {op.register}")
        if AccessMode.WRITE in op.access:
            print(f"  writes {op.register}")
```

## Examples

### Finding All Call Instructions

```python
import quokka
from quokka.types import FunctionType
from quokka.exc import FunctionMissingError

prog = quokka.Program("bash.quokka", "bash")

call_sites = []
for func in prog.values():
    if func.type != FunctionType.NORMAL:
        continue
    for block in func.values():
        for addr, inst in block.items():
            if inst.mnemonic in ("call", "bl", "blx", "jal"):
                try:
                    target = inst.call_target
                    callee_name = target.name
                except FunctionMissingError:
                    callee_name = "indirect"
                call_sites.append({
                    "caller": func.name,
                    "site": hex(addr),
                    "callee": callee_name,
                })

print(f"Found {len(call_sites)} call sites")
```

### Finding Dangerous Function Calls

```python
from quokka.exc import FunctionMissingError

DANGEROUS = {"strcpy", "gets", "sprintf", "system",
             "strcat", "scanf", "vsprintf"}

hits = []
for func in prog.values():
    for block in func.values():
        for addr, inst in block.items():
            try:
                target = inst.call_target
            except FunctionMissingError:
                continue
            if target.name in DANGEROUS:
                hits.append((func.name, hex(addr), target.name))

for caller, site, callee in hits:
    print(f"  [{site}] {caller} → {callee}")
```

## Instruction Cheatsheet

| Attribute / Method | Type | Description |
|--------------------|------|-------------|
| `inst.address` | `int` | Virtual address |
| `inst.size` | `int` | Size in bytes |
| `inst.mnemonic` | `str` | Mnemonic string |
| `inst.bytes` | `bytes` | Raw instruction bytes |
| `inst.is_thumb` | `bool` | ARM Thumb mode flag |
| `inst.operands` | `list[Operand]` | Decoded operands |
| `inst.cs_inst` | `CsInsn` | Capstone instruction object |
| `inst.pcode_insts` | `list[PcodeOp]` | Lifted P-code operations |
| `inst.strings` | `list[str]` | Referenced string literals |
| `inst.constants` | `list[int]` | Immediate constant values |
| `inst.comments` | `Iterable[str]` | IDA comments on instruction |
| `inst.call_target` | `Function` | Resolved call target (raises if none) |
| `inst.callees` | `list[int]` | Addresses of call targets |
| `inst.callers` | `list[int]` | Addresses of callers |
| `inst.is_call` | `bool` | True if this is a call |
| `inst.is_jump` | `bool` | True if this is a jump |
| `inst.is_conditional_jump` | `bool` | True if conditional jump |
| `inst.is_dynamic` | `bool` | True if indirect call/jump |
| `inst.data_refs_from` | `list` | Data xrefs from this instruction |
| `inst.data_read_refs_from` | `list` | Data read xrefs from this instruction |
| `inst.data_write_refs_from` | `list` | Data write xrefs from this instruction |
| `inst.data_refs_to` | `list` | Data xrefs to this instruction |
| `inst.code_refs_from` | `list[int]` | Code xrefs from (jump/call targets) |
| `inst.code_refs_to` | `list[int]` | Code xrefs to (who jumps/calls here) |
| `inst.type_refs_from` | `list[TypeReference]` | Type xrefs from this instruction |
| `inst.is_fall_through(addr)` | `bool` | Check if addr is the fall-through target |

## Operand Cheatsheet

| Attribute / Method | Type | Description |
|--------------------|------|-------------|
| `op.type` | `OperandType` | `REGISTER`, `IMMEDIATE`, `MEMORY`, `OTHER` |
| `op.value` | `Any` | Typed value: int (imm), str (reg), mem object |
| `op.register` | `str` | Register name (empty if not a register) |
| `op.access` | `AccessMode` | `READ`, `WRITE`, or `READ\|WRITE` |
| `op.data_refs_from` | `list` | Data objects/functions referenced by this operand |
| `op.code_refs_from` | `list[int]` | Code addresses referenced by this operand |
| `op.type_refs_from` | `list[TypeReference]` | Type references on this operand |
| `str(op)` | `str` | Human-readable operand string |

```python
from quokka.types import OperandType, AccessMode

for op in inst.operands:
    match op.type:
        case OperandType.REGISTER:
            print(f"reg={op.register}  access={op.access}")
        case OperandType.IMMEDIATE:
            print(f"imm={op.value:#x}")
        case OperandType.MEMORY:
            print(f"mem={op.value}  refs={op.data_refs_from}")
```

## See Also

- [P-code Lifting](pcode.md) — architecture-independent IR via `inst.pcode_insts`
- [Cross-References](xrefs.md) — `inst.code_refs_from`, `inst.data_refs_from`, etc.
