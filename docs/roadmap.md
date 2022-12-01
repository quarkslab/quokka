# Roadmap

`Quokka` is not perfect and some features could be improved.
The list below is not a **Roadmap** _per se_ but more like a whishlist.

Do not hesitate to open Issues for requesting features.

## Export Information

* [ ] Types Information
 > For the moment, Quokka does not export types information. This feature would be super useful for various analyses.
* [ ] Stack Variable
 > IDA defines stack variables in the function. Exporting them could be valuable for some workflows 
* [ ] Decompiler
 > Hex-Rays generates a pseudo C-code from binary code. Exporting it as well could also be nice 
* [ ] Operands Data
 > While the operands are exported, it is hard to understand them outside IDA without having the disassembler 
 > documentation. Exporting information on them could be interesting.

## Refactor

* [ ] Rewrite the Reference Manager
  > The `Reference Manager` is hard to understand, to maintain and to use. Plus, it has some performances issues. It has
  > to be rewritten to be improved while not losing any functionalities.

* [ ] Remove the interface for Function Chunks
  > A Function Chunk is an IDA abstraction for function parts. However, it is meaningless to expose them in the user 
  interface because users do not care about them.

* [ ] Use `weakref` for Program
  > `Program` has backref in most items in `Quokka`. However, we should use `weakref` to allow the garbage collector to 
  > do its magic when cleaning some parts of the program.
  
## Disassemblers

* [ ] Quokka for Ghidra / Binary Ninja
  > While IDA works nicely, some researchers have moved to other disassemblers. Having an export working for Binary Ninja
  > and Ghidra could help Quokka adoption!

## Misc

* [ ] Support [Fat binaries](https://en.wikipedia.org/wiki/Fat_binary)
  > IDA supports disassembling Fat Binaries but Quokka will only export the first one. One nice feature would be to 
  > select which one to export 
* [ ] Verify the support for unknown architectures
  >  Quokka should export any binary but it has been barely tested with other architectures.

## Documentation

* [ ] Document Export Modes
  > Quokka has three export modes, but only one is properly documented (NORMAL)
