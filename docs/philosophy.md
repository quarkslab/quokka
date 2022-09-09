# Philosophy

`Quokka` and its companion plugin `python-quokka` were created in order to 
manipulate a binary without using IDA. To be usable, we needed something 
(reasonably) fast and compact. It leads to the following properties we try 
to enforce.

## Compact
As few as possible data should be duplicated in the export file. For this, 
a lot of index table are used over the export.

## Fast
Even if only done once, the export must be as fast as possible.

## Intuitive
The goal is simple: be more intuitive than IDA Python API.