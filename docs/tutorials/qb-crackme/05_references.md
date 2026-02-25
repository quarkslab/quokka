# References

One important element in programs are the relations between different 
subcomponents.

We denote links between two element as `References`.

## Reference Types

`quokka` uses several Reference Types listed below that are self-explanatory.

```python title="Extract of types.py" 
class RefType(enum.IntEnum):
    UNKNOWN = 0
    JMP_UNCOND = 1
    JMP_COND = 2
    JMP_INDIR = 3
    CALL = 4
    CALL_INDIR = 5
    DATA_READ = 6
    DATA_WRITE = 7
    DATA_INDIR = 8
    TYPE_SYMBOL = 9
```

## Call References

A `Call` reference is a link from one `Instruction` to a `Chunk`.
Usually, the mnemonic is something like `call`.

For instance:
```python
import quokka

prog = quokka.Program('docs/samples/qb-crackme.quokka', 'docs/samples/qb-crackme')

inst: quokka.Instruction = prog.get_instruction(0x804950f)
target: quokka.Chunk = inst.call_target
print(f"Inst {inst} calls `{target.name}`")
# Inst <call 0x8049270> calls `get_input`
```

## Data References

Sometimes, instruction manipulates `Data`.

```python
import quokka
prog = quokka.Program('docs/samples/qb-crackme.quokka', 'docs/samples/qb-crackme')

inst = prog.get_instruction(0x8049287)
print(inst.cs_inst)
# <CsInsn 0x8049287 [a140e00408]: mov eax, dword ptr [0x804e040]>

for data in inst.data_refs_from:
	print(f"{data.type}: {data.address} {data.value}")
	# DataType.DOUBLE_WORD : 0x804e040 None
```

