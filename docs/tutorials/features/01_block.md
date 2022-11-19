# Block features

In this 1st part, let's look at how to extract the block features for the paper.

## Final snippet

```python
from typing import Dict, Union, List
import quokka

# Use the code from arch.py in this repo
# Originally 
# https://github.com/Cisco-Talos/binary_function_similarity/blob/main/IDA_scripts/IDA_acfg_features/core/architecture.py
ARCH_MNEM = ...

FeaturesDict = Dict[str, Union[int, List[str], List[int]]]

def get_bb_features(block: quokka.Block) -> FeaturesDict:

    mnemonics = [inst.cs_inst.mnemonic for inst in block.instructions]
    arch = block.program.isa.name

    return {
        "bb_len": block.size, # (1)!
        # List features
        "bb_numerics": block.constants, # (2)!
        "bb_strings": block.strings, # (3)!
        # Numeric features
        "n_numeric_consts": len(block.constants), # (4)!
        "n_string_consts": len(block.strings), # (5)!
        "n_instructions": len(mnemonics), # (6)!
        "n_arith_instrs": sum(
            1 for m in mnemonics if m in ARCH_MNEM[arch]["arithmetic"]  # (7)!
        ),
        "n_call_instrs": sum(1 for m in mnemonics if m in ARCH_MNEM[arch]["call"]),
        "n_logic_instrs": sum(1 for m in mnemonics if m in ARCH_MNEM[arch]["logic"]),
        "n_transfer_instrs": sum(
            1 for m in mnemonics if m in ARCH_MNEM[arch]["transfer"]
        ),
        "n_redirect_instrs": sum(
            1
            for m in mnemonics
            if (m in ARCH_MNEM[arch]["unconditional"])
            or (m in ARCH_MNEM[arch]["conditional"])
            or (m in ARCH_MNEM[arch]["call"])
        ),
    }
```

1. First, let's take the len of the block as its size
2. The list of numerics constants used in the block is accessible using the `.constants` attribute
3. The list of strings found in the block is accessible by `.strings`
4. The number of constants is simply found using the `len` of the constants list
5. The number of strings is simply found using the `len` of the strings list
6. We count the number of instruction using the number of the mnemonics in the list.
7. Classify instructions using the `ARCH_MNEM` mapping provided

## ARCH_MNEM

This mapping has been created by the paper's authors to classify the instructions in each architecture. For example, 
the mnemonic used to _touch_ the stack in `ARM` are the following:

```python
ARCH_MNEM = {}
ARCH_MNEM["ARM"]["stack"] = {
    'pop',
    'popeq',
    'popne',
    'pople',
    'pophs',
    'poplt',
    'push'
}
```
## Obtaining the mnemonics

If you paid attention to the snippet, this line was used to obtain the mnemonics:
```python
...
mnemonics = [inst.cs_inst.mnemonic for inst in block.instructions]
...
```

Why did we use the `cs_inst` attribute instead of the more simple one `mnenomic` from the `Instruction` class?

To simply demonstrate the usage of the `capstone` bindings.
