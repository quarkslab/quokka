# Functions

The `Function` object represents a single function in the analyzed binary. This page covers function properties, types, thunk handling, call relationships, and CFG access.

## The `Function` Object

`Function` is a `dict` subclass:

- Keys: **block start addresses**
- Values: **`Block`** objects

```python
func = prog.get_function("main", approximative=False)

print(func.name)   # "main"
print(func.start)  # 0x401a50  (first address)
print(func.end)    # 0x401b20  (last address + 1)
print(func.size)   # 208 bytes

# Number of basic blocks
print(len(func))   # 12

# Iterate blocks by address
for block_addr, block in func.items():
    print(f"  block @ 0x{block_addr:x} ({len(block)} instructions)")
```

## Function Types

Not all functions are equal:

```python
from quokka.types import FunctionType

func.type  # FunctionType.NORMAL
```

| Type | Description |
|------|-------------|
| `NORMAL` | Regular function in the binary |
| `IMPORTED` | External symbol (e.g. `malloc` from libc) |
| `LIBRARY` | Identified library code (FLIRT signature match) |
| `THUNK` | Short stub that jumps to another function |
| `EXTERN` | External / unresolved |

```python
# Filter by type
normal_funcs = [f for f in prog.values()
                if f.type == FunctionType.NORMAL]
```

!!! warning
    Imported functions have **no blocks**. Always check `func.type` before accessing `func.graph` or iterating over blocks.

## Thunk Functions

Thunks are compiler-generated stubs that forward calls:

```
THUNK_malloc → (jmp) → malloc@plt → (jmp) → malloc (libc)
```

They pollute the call graph with meaningless intermediate nodes.

```python
from quokka import dereference_thunk

# Get the real function behind a thunk
thunk = prog.get_function("j_malloc")
real = dereference_thunk(thunk)   # → malloc
print(real.name)  # "malloc"

# Effective degrees (resolving thunks)
from quokka import resolve_effective_degrees
in_deg, out_deg = resolve_effective_degrees(func)
```

## Callers & Callees

```python
func = prog.get_function("process_input", approximative=False)

# Functions called by func
print("Callees:")
for callee in func.callees:
    print(f"  → {callee.name}")

# Functions that call func
print("Callers:")
for caller in func.callers:
    print(f"  ← {caller.name}")

# Graph degrees
print(func.in_degree)   # how many functions call this
print(func.out_degree)  # how many functions this calls
```

## Strings

```python
# All strings referenced by the function
for s in func.strings:
    print(repr(s))

# Example output:
# "Usage: %s [-h] [-v] filename"
# "Error: file not found"
```

!!! tip
    To find all data references from a function, iterate over its instructions
    and collect their `data_refs_from`:

    ```python
    data_refs = []
    for inst in func.instructions:
        data_refs.extend(inst.data_refs_from)
    ```

## Control Flow Graph

The `func.graph` property returns a `networkx.DiGraph` where:

- **Nodes** are block start addresses
- **Edges** are `(src_addr, dst_addr, {type: RefType})` tuples

```python
import networkx as nx

cfg = func.graph

print(f"Blocks: {cfg.number_of_nodes()}")
print(f"Edges:  {cfg.number_of_edges()}")

# Cyclomatic complexity (McCabe): M = E - N + 2P  (P=1 for a connected CFG)
M = cfg.number_of_edges() - cfg.number_of_nodes() + 2
print(f"Cyclomatic complexity: {M}")
```

## Call Graph Patterns

```python
from quokka.types import FunctionType
import networkx as nx

cg = prog.call_graph  # program-level DiGraph

# Leaf functions (no callees)
leaves = [prog[n] for n, d in cg.out_degree() if d == 0
          and n in prog and prog[n].type == FunctionType.NORMAL]

# Root functions (no callers — potential entry points)
roots = [prog[n] for n, d in cg.in_degree() if d == 0
         and n in prog and prog[n].type == FunctionType.NORMAL]

# Longest call chain
longest = nx.dag_longest_path(cg)
```

## Function Attributes Quick Reference

```python
func.name             # str
func.start            # int (first address)
func.end              # int (last address + 1)
func.size             # int (bytes)
func.type             # FunctionType
func.in_degree        # int (raw caller count)
func.out_degree       # int (raw callee count)
func.callees          # list[Function]
func.callers          # list[Function]
func.strings          # list[str]
func.graph            # networkx.DiGraph (CFG)
func.in_function(addr)  # bool: is addr inside func?
func.get_block(addr)    # Block at addr
```

## Example: Top Complexity Functions

```python
import quokka
from quokka.types import FunctionType

prog = quokka.Program("bash.quokka", "bash")

results = []
for func in prog.values():
    if func.type != FunctionType.NORMAL:
        continue
    cfg = func.graph
    n, e = cfg.number_of_nodes(), cfg.number_of_edges()
    complexity = e - n + 2
    results.append((complexity, func.name, func.start))

results.sort(reverse=True)
for complexity, name, addr in results[:10]:
    print(f"  CC={complexity:4d}  {name} @ 0x{addr:x}")
```

## Summary

- `Function` is a dict of blocks, keyed by block address
- **FunctionType**: `NORMAL`, `IMPORTED`, `LIBRARY`, `THUNK`, `EXTERN`
- Thunks need dereferencing (`dereference_thunk`) for accurate call graph analysis
- `func.callees` / `func.callers` provide direct navigation
- `func.graph` is a `networkx.DiGraph` (CFG)
- **Cyclomatic complexity**: `E - N + 2`
