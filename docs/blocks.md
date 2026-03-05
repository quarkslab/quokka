# Basic Blocks & CFG

A **basic block** is a maximal straight-line sequence of instructions with one entry point and one exit point. This page covers the `Block` object, block types, CFG navigation, and common analysis patterns.

## What is a Basic Block?

```
  ┌─────────────────────┐
  │  mov eax, [rdi]     │
  │  add eax, 1         │  ← basic block
  │  cmp eax, 0         │
  │  jz  exit_label     │
  └──────┬──────────────┘
         │  (conditional)
    ┌────┴────┐  ┌──────────┐
    │ (false) │  │ (true)   │
    └─────────┘  └──────────┘
```

## The `Block` Object

`Block` is a `MutableMapping` keyed by **instruction address**:

```python
func = prog.get_function("parse_args", approximative=False)

# Get the entry block
entry = func.get_block(func.start)

# Or access via the function dict
entry = func[func.start]

print(f"Block @ 0x{entry.start:x}")
print(f"  Instructions: {len(entry)}")
print(f"  Type:         {entry.type}")

# Iterate instructions
for addr, inst in entry.items():
    print(f"  0x{addr:x}: {inst}")
```

## Block Types

```python
from quokka.types import BlockType

entry.type  # BlockType.NORMAL
```

| Type | Meaning |
|------|---------|
| `NORMAL` | Standard block — falls through or jumps |
| `RET` | Ends with a return instruction |
| `NORET` | Ends with a call to a no-return function |
| `INDJUMP` | Ends with an indirect jump (switch table) |
| `CNDRET` | Conditional return |
| `ENORET` | External no-return |
| `ERROR` | Disassembly error |
| `EXTERN` | External / unresolved |

## CFG Navigation

The CFG is a `networkx.DiGraph` accessible via `func.graph`:

```python
cfg = func.graph  # networkx DiGraph

# Successors of a block (blocks reachable in one step)
successors = list(cfg.successors(entry_addr))

# Predecessors of a block
predecessors = list(cfg.predecessors(some_block_addr))

# Via Block convenience properties
block = func.get_block(func.start)
for succ_addr in block.successors:
    print(f"  → 0x{succ_addr:x}")
for pred_addr in block.predecessors:
    print(f"  ← 0x{pred_addr:x}")
```

## CFG Edge Types

Edges carry a `type` attribute (a `RefType`):

```python
for src, dst, data in cfg.edges(data=True):
    ref_type = data.get("type")
    print(f"  0x{src:x} → 0x{dst:x}  [{ref_type}]")
```

| Edge type | Meaning |
|-----------|---------|
| `JMP_UNCOND` | Unconditional jump |
| `JMP_COND` | Conditional jump (true branch) |
| `JMP_INDIR` | Indirect jump (switch table) |
| `CALL` | Direct call |
| `CALL_INDIR` | Indirect call |

## Loop Detection

```python
import networkx as nx

cfg = func.graph

# Does the CFG have back-edges? (cycles = loops)
has_loops = not nx.is_directed_acyclic_graph(cfg)

# Find all simple cycles
cycles = list(nx.simple_cycles(cfg))
print(f"Function has {len(cycles)} loops")

# Dominator tree
dom_tree = nx.immediate_dominators(cfg, func.start)
```

## Common Patterns

### Finding Conditional Blocks

```python
# Blocks with exactly 2 successors = conditional jump
for block_addr in cfg.nodes():
    succs = list(cfg.successors(block_addr))
    if len(succs) == 2:
        block = func.get_block(block_addr)
        print(f"Conditional block @ 0x{block_addr:x}")
        print(f"  True  → 0x{succs[0]:x}")
        print(f"  False → 0x{succs[1]:x}")
```

### Finding Return Blocks

```python
from quokka.types import BlockType

ret_blocks = [b for b in func.values()
              if b.type == BlockType.RET]
```

### Structured Traversal

```python
import networkx as nx

cfg = func.graph

# BFS from entry
for block_addr in nx.bfs_tree(cfg, func.start).nodes():
    block = func.get_block(block_addr)
    print(f"Block 0x{block_addr:x}: {len(block)} insts, type={block.type}")

# Topological order (for acyclic CFGs)
try:
    for block_addr in nx.topological_sort(cfg):
        print(f"0x{block_addr:x}")
except nx.NetworkXUnfeasible:
    print("CFG has cycles — use BFS instead")
```

### Entry and Exit Blocks

```python
# Entry = the block at func.start
entry = func.get_block(func.start)

# Exit blocks = blocks with no successors in the CFG
exits = [addr for addr in cfg.nodes()
         if cfg.out_degree(addr) == 0]

# Or using BlockType
from quokka.types import BlockType
exits = [b for b in func.values()
         if b.type in (BlockType.RET, BlockType.NORET)]
```

## Example: Complexity Analyzer

```python
import networkx as nx
from quokka.types import FunctionType

def analyze_cfg(func):
    """Return (n_blocks, n_edges, cyclomatic_complexity, n_loops)"""
    cfg = func.graph
    n = cfg.number_of_nodes()
    e = cfg.number_of_edges()
    cc = e - n + 2  # McCabe cyclomatic complexity
    loops = len(list(nx.simple_cycles(cfg)))
    return n, e, cc, loops

for func in prog.values():
    if func.type != FunctionType.NORMAL or len(func) < 5:
        continue
    n, e, cc, loops = analyze_cfg(func)
    if cc > 20:
        print(f"HIGH COMPLEXITY: {func.name:30s} CC={cc} loops={loops}")
```

## Summary

- `Block` is a `MutableMapping` of instructions, keyed by address
- **BlockType**: `NORMAL`, `RET`, `NORET`, `INDJUMP`, `CNDRET`, `ERROR`
- `func.graph` is a `networkx.DiGraph` of block addresses
- CFG edges carry `RefType` (`JMP_COND`, `JMP_UNCOND`, `CALL`…)
- `block.successors` / `block.predecessors` for convenient navigation
- Use networkx algorithms: BFS, cycle detection, dominator trees
