# Usage

## Export plugin

!!! note

    This requires a working IDA installation.


- Either using command line:
```commandline
$ idat64 -OQuokkaAuto:true -A /path/to/hello.i64
```

Note: We are using `idat64` and not `ida64` to increase the export speed
because we don't need the graphical interface.

- Using the plugin shortcut inside IDA: (by default) Alt+A

### Export Options

To pass option to an IDA plugin, use the ``-O`` switch on the command line.
Ex: ``-OQuokka<OPTION_NAME>:<OPTION_VALUE>``.

#### Log - Log level
* Usage: ``-OQuokkaLog:<LEVEL>``
* Values: Debug,_Info_,Error

This option toggle the reporting of the exporter.

Note: The debug log level also prints the line and the function.

#### File - Output filename
* Usage: ``-OQuokkaFile:<NAME>``
* Values: A path where the user is allowed to write

Use this option to override the file written by quokka.
If none is given, <path_to_idb>.quokka is used.

#### Auto - Auto mode
* Usage: ``-OQuokkaAuto:<NON_EMPTY_STRING>``

Use this option to launch quokka directly from the command line.

#### Export Level
* Usage: ``-OQuokkaMode:<MODE>``
* Values: LIGHT, _NORMAL_, FULL

Controls the export level for the instructions:

* If the ``Light`` mode is selected, only the block starting addresses will be 
exported.
* For ``Normal``, the instructions with all IDA values will be exported. 
  However, it is challenging to interpret them because you have to read IDA API.
* For ``Full``, the instruction **and** the string representation of the 
  instruction is exported.

Example:

=== "Light mode"

    ```python
	prog.proto.instructions == []
    ```

=== "Normal mode"

    ```python
    prog.proto.instructions[0] = 
      size: 3
      mnemonic_index: 3
      operand_index: 1
      operand_index: 6
    ```

=== "Full mode"

    ```python
    prog.proto.instructions[0] =
      size: 3
      mnemonic_index: 3
      operand_index: 1
      operand_index: 6
      operand_strings: 1
      operand_strings: 6
    ```

!!! tip "How to choose a mode?"
    
    By default, use the ``Normal`` mode.
    If you know you are going to ask for another disassembler for specific bytes 
    (or have reversed the IDA way of storing data), consider using the ``Light`` 
    mode.
    Finally, if you have an exotic architecture, you may be interested in the full
    disassembly: in this case, use the ``Full`` mode.
