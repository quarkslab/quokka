# Experimental integration with ghidra

This is an experimental integration of quokka as a Ghidra plugin.

## How to compile

The building system uses gradle.

```shell
./gradlew -PGHIDRA_INSTALL_DIR=PATH_TO_GHIDRA_INSTALLATION
```

This will produce the ghidra plugin on `dist/`.
To install it on ghidra you need to `Open Ghidra` > `File` >
`Install extenstion` > `+ (Add extension) [in the top right corner]` >
`Select the file under dist/ (for example: dist/ghidra_10.3_DEV_20230530_Quokka.zip)`