# Philosophy

`Quokka` and its bindings were created in order to manipulate a binary without
using IDA. To be usable, we needed something (reasonably) fast and compact. It
leads to the following properties we try to enforce:

* Exhaustive
  The plugin should export as much data as possible from IDA
* Compact
  The export file should be as compact as possible to reduce disk usage.
* Fast
  Waiting for the export should be kept as a minimum.
* Intuitive
  The plugin should be usable without documentation with an intuitive interface.
