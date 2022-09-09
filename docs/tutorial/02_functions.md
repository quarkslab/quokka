# Functions

One of the most common binary abstraction level is the `function`. Thus, 
`quokka` offers nicer way to interact to them (compared to the default IDA API).

!!! note "Prerequisites"
    For this part of the tutorial, I asssume you already have a working 
    installation of quokka and you already exported `qb-crackme`.


## Finding functions

```python
import quokka

prog: quokka.Program

# First way: accessing a function by its address
func = prog[0x8049000]
print(func)

# This is <Function _init_proc at 0x8049000>

# Second solution: by its name
func = prog.fun_names['_init_proc']

# Third: by the get_function method
prog.get_function(name='_init_pr',  # Something in the name 
                  approximative=True, # Accept non-exact match
                  normal=True) # Only regular functions
```

!!! question "Function Types ?"
    Binary functions have types in IDA (e.g. NORMAL, THUNK ...). The 
    `get_function` method allows to restrict results to the NORMAL one : 
    functions that are defined inside the program with regular body.

    The complete list of function types is:

    | Type | Definition |
    | ---- | ---------- |
    | EXTERN | Function defined in an _external_ library |
    | IMPORTED |  |
    | NORMAL | Regular functions |
    | LIBRARY | |
    | THUNK | Thunk functions |
    | INVALID | Errored type, should not exist |
    
    The `type` of a function is accessible through `function.type` attribute.


## The `Function` object
Like most of the object in `quokka`, the function object is in itself a mapping. 
The keys are the address and the values the corresponding **chunks**.

!!! info
    A chunk is an IDA specific concept to deal with code reuse across functions. 
    A function must have at least one chunk but a chunk may be shared by multiple 
    functions.
    See [Igor's explanation](https://hex-rays.com/blog/igors-tip-of-the-week-86-function-chunks/)

!!! warning
    The direct successors of a function are chunks. However, the interface of 
    function and chunk is similar and most of  the functions works the same on 
    the both levels.

!!! example
    ```python
    
    prog: quokka.Program
    func = prog.fun_names['_init_proc']
    
    print(f"Function {func.name} calls {len(func.calls)} function(s).")
    # Print: Function _init_proc calls 1 function(s).
    ```

## Manipulating function
The `Function` class offers fast accessors to common properties. The snippet 
below list some of them :
```python
import quokka

prog = quokka.Program('docs/samples/qb-crackme.Quokka', 'docs/samples/qb-crackme')
func = prog.fun_names['level_1']

print(f'Func {func.name} starts at 0x{func.start:x} and finished at 0x{func.end:x}')

# Print the strings in the function
print(func.strings)

# Does the function uses constants ?
if func.constants:
    print(f'{func.name} use constants')

# What are the names of the functions called by this one ?
for called in func.calls:
    print(called.name)
```

## Function CFG
The CFG of the function is accessible through the `func.graph` attribute. 
It is a `networkx.DiGraph` where the nodes are the blocks (of all the chunks). 

!!! warning
    You must use the `get_block` method to retrieve a block from a function 
    object as the dict in itself only refers `Chunk`.


## Chunks & Super chunks

We already stated that Functions are composed of Chunks, themselves composed of 
Basic Blocks. However, the Chunk abstraction is never really used... Thus, most
accessors at the function level propagate the requests at the block level.

### Super Chunks
Super chunks are an abstraction used to deal with functions have multiple 
non-connected subcomponents.

A `SuperChunk` is composed of `Chunks` itself.

To iterate through all the chunks of a program a special method exists : 
`program.iter_chunk`.
This method deals with SuperChunks and Functions to enumerate all the chunks 
defined in the program.
