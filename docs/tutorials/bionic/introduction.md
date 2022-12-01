# Bionic in Android

In this tutorial, we will learn how to extract the user mapping in the `Android` libc: `Bionic`.

## Context

Android, the mobile operating system, uses a custom `libc`: `bionic`. A few notable changes exist from the classic 
implementation of the libc found on most desktop Linux systems. One of them is that the user table is embedded within
the binary.

## Objective

Automatically extract the **user mapping** from the binary[^1].

## Requirements

* A working Quokka Installation
* The [bionic library](https://raw.githubusercontent.com/quarkslab/quokka/main/docs/tutorials/bionic/samples/libc.so) (`sha256sum: 5975c8366fce5e47ccdf80f5d01f3e4521fee3b1dcf719243f4e4236d9699443`)
* An [export](https://raw.githubusercontent.com/quarkslab/quokka/main/docs/tutorials/bionic/samples/libc.quokka) of the bionic library

## Check requirements

```python
import quokka
bionic = quokka.Program("libc.quokka", "libc.so")
assert bionic is not None
```

## Final words

Once you are set, we can advance to the next steps.

[^1]:
    This exercise is based on an idea from Robin David in his IDA scripting training.