# Blocks

Blocks are parts of a function.
They are in itself dict with a mapping from instruction address to instruction.

## Finding a block

```python
import quokka

# Load the program and get a function
prog = quokka.Program('docs/samples/qb-crackme.quokka', 'docs/samples/qb-crackme')
func = prog.fun_names['level_1']

block_start: int = 0x80494e8

# Method 1 : Get a block through the function
block = func.get_block(address=block_start)

# Method 2 : Get a block from an instruction
inst = prog.get_instruction(block_start)
block = inst.parent
```

## Block attributes

It should be no suprise that a `Block` is also a mapping. Indeed, it holds a
mapping from address to Instructions.

However, it still has some properties

### CFG
A block maintains a list of successors and predecessors (from the CFG).

```python
successor: int
for successor in block.successors:
   assert(successor in block.parent)
```

## Strings, constants and comments
Strings, constants (and other data) are accessible with the eponyms attributes.
Moreover, if a comment has been defined in IDA, it is accessible through 
`comments`.

## Type

Basic blocks have types in IDA which is exported by `quokka`.
Use `block.type` to access it.