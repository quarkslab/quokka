# Solving the crackme

As you have already seen, the sample we use since the beginning of this tutorial
is a (simple) crackme. 

Let's try to see how we can start to solve it with `quokka`.

## Finding the challenges

```python
import quokka

prog = quokka.Program('docs/samples/qb-crackme.Quokka', 'docs/samples/qb-crackme')

# Get the functions name
for func in prog.fun_names:
	if func.startswith("level"):
		print(prog.fun_names[func])
```

It yields to the following results!
```commandline
<Function level0 at 0x80492bc>
<Function level1 at 0x80494e8>
<Function level2 at 0x8049568>
<Function level3 at 0x80495c3>
<Function level4 at 0x80496f0>
<Function level5 at 0x804980c>
<Function level6 at 0x804987e>
<Function level7 at 0x80499af>
<Function level8 at 0x8049b69>
<Function level9 at 0x8049cfe>
```

Great, we have about 10 levels to solve. Let start by the first one.

## Level 0

First, get the function:
```python
func = prog.fun_names["level0"]
```

Then, let's examine it:
```python
# Get the size
print(len(func)) # 1 Chunk
print(len(func[func.start])) # 7 basic blocks
```

We see that the functions have 3 strings:
```python
for str in func.strings:
	print(str)
```

```commandline
0;-LS|iX|:rlAy1ZWr;|+Ab1S3},IV.z*t:%|pHyY_9&AuW*.jJX`<5]z{nB``mEdntH5f#`n={JPGLF0r>ua!ObZE?y.VjfpsZ6rTvD|Y--9E~AXeuY9I2&[iNTIr^]!%dAu-m82$CF#[of+]7RcgdKd.W&~D01j^fI}=Cda+7W)zg:m1[=!]JdiUaq({@H:)+/JZ.z0(!?ekIV55oq-6an3Ag8o)5k-mu,RH1z7fSy:s@K4oQ.TkYg7^i
F00d1e
What's the flag?
```

And it's calling 3 functions:
```python
for chunk in func.calls:
	print(chunk.name)
```

```commandline
get_input
_strlen
_strlen
```

Let's now print the disassembly of the first block to understand what's happening:

```python
for inst in func.get_block(func.start):
    print(inst.cs_inst)
```

```commandline hl_lines="11 16 22"
<CsInsn 0x80492bc [55]: push ebp>
<CsInsn 0x80492bd [89e5]: mov ebp, esp>
<CsInsn 0x80492bf [81ec28020000]: sub esp, 0x228>
<CsInsn 0x80492c5 [c745ec88b00408]: mov dword ptr [ebp - 0x14], 0x804b088>
<CsInsn 0x80492cc [c745e88fb00408]: mov dword ptr [ebp - 0x18], 0x804b08f>
<CsInsn 0x80492d3 [83ec04]: sub esp, 4>
<CsInsn 0x80492d6 [8d85dcfdffff]: lea eax, [ebp - 0x224]>
<CsInsn 0x80492dc [50]: push eax>
<CsInsn 0x80492dd [ff75e8]: push dword ptr [ebp - 0x18]>
<CsInsn 0x80492e0 [ff75ec]: push dword ptr [ebp - 0x14]>
<CsInsn 0x80492e3 [e888ffffff]: call 0x8049270>
<CsInsn 0x80492e8 [83c410]: add esp, 0x10>
<CsInsn 0x80492eb [c745e4a0b00408]: mov dword ptr [ebp - 0x1c], 0x804b0a0>
<CsInsn 0x80492f2 [83ec0c]: sub esp, 0xc>
<CsInsn 0x80492f5 [ff75e4]: push dword ptr [ebp - 0x1c]>
<CsInsn 0x80492f8 [e863fdffff]: call 0x8049060>
<CsInsn 0x80492fd [83c410]: add esp, 0x10>
<CsInsn 0x8049300 [8945e0]: mov dword ptr [ebp - 0x20], eax>
<CsInsn 0x8049303 [83ec0c]: sub esp, 0xc>
<CsInsn 0x8049306 [8d85dcfdffff]: lea eax, [ebp - 0x224]>
<CsInsn 0x804930c [50]: push eax>
<CsInsn 0x804930d [e84efdffff]: call 0x8049060>
<CsInsn 0x8049312 [83c410]: add esp, 0x10>
<CsInsn 0x8049315 [8945dc]: mov dword ptr [ebp - 0x24], eax>
<CsInsn 0x8049318 [c745f400000000]: mov dword ptr [ebp - 0xc], 0>
<CsInsn 0x804931f [c745f0c8000000]: mov dword ptr [ebp - 0x10], 0xc8>
<CsInsn 0x8049326 [eb2c]: jmp 0x8049354>
```

We find the three calls we already saw.

!!! note
	Since we are using `capstone` disassembly here, we don't resolve the call
	target. However, using `func.get_instruction(0x80492e3).call_target.name`
	allows us to recover it!

Let's examine this extract:
```commandline
<CsInsn 0x80492eb [c745e4a0b00408]: mov dword ptr [ebp - 0x1c], 0x804b0a0>
[...]
<CsInsn 0x80492f5 [ff75e4]: push dword ptr [ebp - 0x1c]>
<CsInsn 0x80492f8 [e863fdffff]: call 0x8049060>
```

We load a data and push it on the stack before calling a function.
We can ask `quokka` to help us to identify the calling convention used by the 
binary in two ways: 
```python
from quokka.analysis import Environment, Platform

env = Environment(Platform.LINUX, prog.arch)
print(env.calling_convention)

# Or ask IDA
# This uses the protobuf directly because no accessor is yet available.
print(prog.proto.meta.calling_convention)
```

In `cdecl`, arguments are pushed on the stack. So, we see that the argument of
the `strlen` call is the data loaded from memory.

```python
inst = func.get_instruction(0x80492eb)
print(inst.string)
```

The argument used by the second call at `strlen` is the result of the `get_input`
function.


Let's consider the next block:
```python
first = func.get_block(func.start)
next_block = func.get_block(next(first.successors()))
```

We know there is only one successor because either :
- the first block disassembly ends with an unconditional jump
- `func.graph[first.start]` lists an Unconditional Edge
- `sum(1 for _ in first.successors())` is 1

Our new block has two predecessors: we are in a loop!
```python
list(next_block.predecessors())
```

From now on, we can just navigate in the CFG and see what are the conditions to
complete to solve the level.


## Final words

This toy example is maybe not the best display on why `quokka` could be useful,
but highlights some possibilities.
