# P-code Lifting

Quokka supports lifting native instructions to **Ghidra P-code**, an architecture-independent intermediate representation, via the [`pypcode`](https://github.com/angr/pypcode) library.

!!! note "Optional dependency"
    P-code support requires `pypcode`: `pip install pypcode`

## What is P-code?

P-code lifts native instructions into a small set of atomic operations on typed memory locations called **varnodes**.

**Why use P-code?**

- **Architecture-independent** — write analysis once, run on x86, ARM, MIPS, PowerPC, and more
- **Explicit data-flow** — reads/writes to named varnodes are fully explicit
- **Uniform representation** — complex instructions (flags, implicit effects) are broken down into simple atomic steps

Quokka uses the [`pypcode`](https://github.com/angr/pypcode) Python bindings for Ghidra's SLEIGH engine.

## Entry Points

P-code is available at both instruction and block granularity:

```python
# Per-instruction (IMARK excluded automatically)
ops: list[pypcode.PcodeOp] = inst.pcode_insts

# Per-block (more efficient — one SLEIGH pass for all instructions)
# NOTE: IMARK operations are included; filter them if needed
ops: list[pypcode.PcodeOp] = block.pcode_insts
```

The **block-level** call is faster because it translates the whole block in a single SLEIGH pass. Use **instruction-level** when you need to correlate P-code ops back to a specific native address.

```python
func = prog.get_function("main", approximative=False)
block = func[func.start]

for addr, inst in block.items():
    print(f"0x{addr:x}  {inst.mnemonic}")
    for op in inst.pcode_insts:
        print(f"      {op}")
```

## `PcodeOp` — One Atomic Operation

Each P-code operation has the form `output = opcode(input0, input1, ...)`:

| Property | Type | Description |
|----------|------|-------------|
| `op.opcode` | `pypcode.OpCode` | The operation kind (e.g. `INT_ADD`, `LOAD`) |
| `op.output` | `pypcode.Varnode \| None` | Destination varnode (`None` for `STORE`, branches) |
| `op.inputs` | `list[pypcode.Varnode]` | Source operands |
| `str(op)` | `str` | Human-readable form |

```python
for op in inst.pcode_insts:
    print(op.opcode.name)          # "INT_ADD"
    if op.output:
        print(f"  → {op.output}")  # "(register, 0x28, 8)"
    for vn in op.inputs:
        print(f"  ← {vn}")
```

## Concrete Example: `push rbp` → 3 P-code Ops

Native instruction: `push rbp` (`0x55`)

```
COPY   unique[27d80:8] = RBP          # save RBP to a temp
INT_SUB  RSP = RSP - 0x8             # decrement stack pointer
STORE  *[ram]RSP = unique[27d80:8]   # write saved RBP to stack
```

Each line is a `PcodeOp`:

- `COPY`: `output=unique[27d80:8]`, `inputs=[register RBP]`
- `INT_SUB`: `output=register RSP`, `inputs=[register RSP, const 0x8]`
- `STORE`: `output=None`, `inputs=[const spaceid, register RSP, unique[27d80:8]]`

!!! tip
    One native instruction expands to multiple P-code ops that make implicit effects (like stack pointer updates) explicit.

## `Varnode` — A Typed Memory Location

A varnode is a triple: **(space, offset, size_in_bytes)**

| Property | Type | Description |
|----------|------|-------------|
| `vn.space` | `pypcode.AddrSpace` | Which address space |
| `vn.offset` | `int` | Offset within that space |
| `vn.size` | `int` | Width in bytes |
| `vn.getRegisterName()` | `str` | Register name if in `register` space, else `""` |
| `str(vn)` | `str` | Human-readable, e.g. `"RBP"` or `"unique[27d80:8]"` |

```python
for vn in op.inputs:
    name = vn.getRegisterName()
    if name:
        print(f"  reg {name} ({vn.size} bytes)")
    else:
        print(f"  {vn.space.name}[{hex(vn.offset)}:{vn.size}]")
```

## Address Spaces

The `vn.space.name` string identifies the varnode's kind:

| Space name | Meaning | Typical usage |
|-----------|---------|--------------|
| `"register"` | CPU register file | `RAX`, `RBP`, `ZF`, `CF`… |
| `"ram"` | Main memory | Load/store targets |
| `"const"` | Immediate constant | Literal values (offset = value) |
| `"unique"` | Temporary / scratch | SLEIGH-internal temporaries |

```python
def describe_varnode(vn) -> str:
    name = vn.space.name
    if name == "register":
        return vn.getRegisterName() or f"reg@{hex(vn.offset)}"
    if name == "const":
        return hex(vn.offset)
    if name == "unique":
        return f"tmp[{hex(vn.offset)}:{vn.size}]"
    return f"*{name}[{hex(vn.offset)}:{vn.size}]"
```

## OpCode Categories

| Category | Opcodes (examples) |
|----------|--------------------|
| **Data transfer** | `COPY`, `LOAD`, `STORE` |
| **Integer arithmetic** | `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_2COMP` |
| **Integer comparison** | `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_SLESS` |
| **Bitwise / shifts** | `INT_AND`, `INT_OR`, `INT_XOR`, `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT` |
| **Sign/zero extend** | `INT_SEXT`, `INT_ZEXT`, `SUBPIECE`, `PIECE` |
| **Boolean** | `BOOL_AND`, `BOOL_OR`, `BOOL_XOR`, `BOOL_NEGATE` |
| **Float** | `FLOAT_ADD`, `FLOAT_MULT`, `FLOAT_LESS`, `FLOAT_INT2FLOAT`… |
| **Control flow** | `BRANCH`, `CBRANCH`, `BRANCHIND`, `CALL`, `CALLIND`, `RETURN` |
| **Marker** | `IMARK` *(instruction boundary — filtered out in `inst.pcode_insts`)* |

```python
from pypcode import OpCode

if op.opcode == OpCode.LOAD:
    addr_vn = op.inputs[1]   # [0] = spaceid, [1] = address
    dest_vn = op.output
```

## Examples

### Find All Memory Reads

```python
import quokka
from pypcode import OpCode

prog = quokka.Program("binary.quokka", "binary")

reads = []
for func in prog.values():
    for block in func.values():
        for addr, inst in block.items():
            for op in inst.pcode_insts:
                if op.opcode == OpCode.LOAD:
                    # inputs: [spaceid_const, address_varnode]
                    addr_vn = op.inputs[1]
                    reads.append({
                        "inst_addr": hex(addr),
                        "from": str(addr_vn),
                        "dest": str(op.output),
                    })

print(f"{len(reads)} memory reads found")
for r in reads[:5]:
    print(f"  {r['inst_addr']}: {r['dest']} = *[{r['from']}]")
```

### Detect Constant Comparisons

Find all instructions that compare a variable against a constant (e.g. `cmp rax, 0`):

```python
from pypcode import OpCode

CMP_OPS = {OpCode.INT_EQUAL, OpCode.INT_NOTEQUAL,
           OpCode.INT_LESS, OpCode.INT_SLESS,
           OpCode.INT_LESSEQUAL, OpCode.INT_SLESSEQUAL}

for func in prog.values():
    for block in func.values():
        for addr, inst in block.items():
            for op in inst.pcode_insts:
                if op.opcode not in CMP_OPS:
                    continue
                # Check if one input is a constant
                for vn in op.inputs:
                    if vn.space.name == "const":
                        print(f"0x{addr:x}  {inst.mnemonic}: "
                              f"compare vs {hex(vn.offset)}")
```

## Error Handling

```python
import quokka

try:
    for op in inst.pcode_insts:
        ...
except quokka.PypcodeError:
    # Raised for BadDataError (invalid bytes) or UnimplError (unsupported opcode)
    pass
```

## Quick Reference

| Object | Key members | Notes |
|--------|------------|-------|
| `inst.pcode_insts` | `list[PcodeOp]` | Per-instruction; no `IMARK` |
| `block.pcode_insts` | `list[PcodeOp]` | Whole block; `IMARK` included |
| `PcodeOp.opcode` | `pypcode.OpCode` | Operation kind |
| `PcodeOp.output` | `Varnode \| None` | Destination (`None` for STORE/branch) |
| `PcodeOp.inputs` | `list[Varnode]` | Source operands |
| `str(PcodeOp)` | `str` | Human-readable dump |
| `Varnode.space` | `AddrSpace` | Address space |
| `Varnode.space.name` | `str` | `"register"`, `"ram"`, `"const"`, `"unique"` |
| `Varnode.offset` | `int` | Offset in space (= value for `"const"`) |
| `Varnode.size` | `int` | Width in bytes |
| `Varnode.getRegisterName()` | `str` | Register name, `""` if not a register |
| `str(Varnode)` | `str` | Human-readable, e.g. `"RAX"`, `"unique[100:8]"` |
