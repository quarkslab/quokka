# Instructions

Instructions are the main component of a program. `quokka` enables a seamless
interaction with them and offers a first-class support for both `capstone` and 
`pypcode`.

## Finding an instruction
```python
import quokka
prog = quokka.Program('docs/samples/qb-crackme.quokka', 'docs/samples/qb-crackme')

# Method 1 : from the program by its address
inst = prog.get_instruction(0x80494e8)
# print(inst)

# Method 2: by the function
func = prog.fun_names['level1']
inst = func.get_instruction(0x80494e8)

# Method 3: by the block
block = func[func.start]
inst = block[0x80494e8]
```

## Instructions attributes

### Printing the mnemonic
```python
print(inst)              # <Inst push>
print(inst.mnemonic)     # push
```

### Using the `capstone` bindings

If `capstone` is installed, it's possible to access the capstone object by using
`inst.cs_inst`.

```python
print(inst.cs_inst)
# <CsInsn 0x80494e8 [55]: push ebp>
```

With this method, you can access every capstone attributes.
For instance, to get the read registers:
```python
for reg in inst.cs_inst.regs_read:
    print(inst.cs_inst.reg_name(reg))
```

### Mnemonics and operands
The mnemonic is found using `instruction.mnemonic`. In LIGHT mode, it comes from
Capstone decoding; in FULL mode, it comes from the disassembler export.

!!! warning
    There can be discrepancies between the disassembler and Capstone. They may
    not always agree on the disassembly.
    `quokka` tries to fall back to sane values.


### Operands

The instruction operands are listed in the `operands` attribute.
Each operand has a `type` (`REGISTER`, `IMMEDIATE`, `MEMORY`, `OTHER`),
a `value`, and optional cross-reference properties.

See [Instructions & Operands](../../instructions.md) for the full API reference.
