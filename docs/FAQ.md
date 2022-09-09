FAQ
===

## What is `quokka` ?

`quokka` is a tool to manipulate the exported versions of your program. 
The goal is to have an easy to understand, stable and scalable API to query the
(disassembled) binary without relying on having IDA running in the background
nor interacting with its API.

As a bonus, once a binary has been exported, you can close IDA and work only
with the exported file.

## Why not use directly IDA API ?

IDA API has at least two drawbacks (for me) :

* you will need to learn its syntax and how it works:

```Python
# IDA way
inst = ida_ua.insn_t()
ida_ua.decode_insn(inst, 0xABCD)
print(inst.get_canon_mnem())

## Quokka
inst = program.get_instruction(0xABCD)
print(inst.mnemonic)
```

## How does `quokka` works ?
In short, it will write everything to a serialized binary format (namely
 protobuf).
 
## What is exported ?
You may have a look at the protobuf format definition to understand exactly
what is exported but the list here can  give you a nice overview.

### Exported features:
* Meta information (file hash, name, detected compiler, calling convention)
* Segments
* Structures (structs, enumerations and unions)
* Comments (every comments attached to anything)
* Layout (where is the code/data/unknown)
* Functions and their associated Control Flow Graph
* Call Graph
* Instructions (and their operands / mnemonics)
* References (data and code xref)
* Data (bytes, strings, ...)

## What is not exported ?
Pretty much everything else but I think the most important here is the type
information. It will be a nice addition but that's not the best part of IDA
API. 
  
## What are the trade-off ?
TODO(dm)

## Contributing
Every PR is welcome.

### Where to start ?
Grep the code for TODO, some are easy, some require more understanding of the 
code.

### Tips
During development, you may want to use a soft link in the
plugin directory coupled with the option to unload the plugin `PLUGIN_UNL`

```console
user@host:~/quokka/$ ln -sf $(pwd)build/src/quokka*64.so \
    /opt/ida/plugins/
``` 