# Installation

## Python Bindings

### System requirements

- Python >= 3.8

!!! note
    While the IDA plugin requires Linux, the Python bindings work on all
    major platforms (Linux, macOS, Windows).

### Installation

#### Using PIP

```commandline
$ pip install quokka-project
```

### Using the sources

To have the latest version, you can directly download the source from
GitHub and install it locally.

```commandline
$ git clone git@github.com:quarkslab/quokka.git
$ cd quokka
$ python -m venv .quokka-env
$ source .quokka-env/bin/activate
(.quokka-env) $ pip install .
```

!!! note
    The previous snippet creates a virtualenv, which is a good practice to
    manage Python dependencies.

### Using a CI wheel

CI wheels are available directly on the [CI](https://github.com/quarkslab/quokka/packages)

### Final checks

To check the installation worked, run the following commands:

```commandline
$ source .quokka-env/bin/activate
(.quokka-env) $ python -c 'import quokka; print(quokka.__version__)'
```

## IDA Plugin

!!! warning
    The plugin support for **Windows** is experimental.

### From the CI

The plugin is built on the CI and available in the
[Releases](https://github.com/quarkslab/quokka/releases).

To download the plugin, get the file named `quokka_plugin**.so`.

### Building

#### Requirements

- CMake (at least 3.13)
- A reasonably modern compiler supporting at least C++20
- IDA SDK (version 9.1 or higher)
- IDA (9.1 or higher)

#### IDA < 9.2 (The old way)

Since the IDA SDK is still proprietary code, you have to fetch it yourself and provide
its path to cmake through the option `-DIdaSdk_ROOT_DIR:STRING=path/to/sdk`

**NOTE:** This will also work on newer versions but it requires more steps from
the users as they will have to download the SDK themselves.

```console
user@host:~/quokka$ cmake -B build \
                          -S . \
                          -DIdaSdk_ROOT_DIR:STRING=path/to/ida_sdk \
                          -DCMAKE_BUILD_TYPE:STRING=Release
```

#### IDA >= 9.2 (The new way)

The IDA SDK has been [open sourced](https://github.com/HexRaysSA/ida-sdk) so there is no need
anymore to download it separately.

You can use the cmake option `-DIDA_VERSION=<major>.<minor>` to automatically sync it from GitHub.

```console
user@host:~/quokka$ cmake -B build \
                          -S . \
                          -DIDA_VERSION=9.2 \
                          -DCMAKE_BUILD_TYPE:STRING=Release
```

#### Finalize the build

If the first step succeeded, you can now do the actual building.

```console
user@host:~/quokka$ cmake --build build --target quokka_plugin -- -j
```

### Installing the plugin

```console
user@host:~/quokka$ cmake --install build
```

The plugin will also be in `build/quokka-install`. You can
copy it to IDA's user plugin directory:

```console
user@host:~/quokka$ cp build/quokka-install/quokka*64.so $HOME/.idapro/plugins/
```

### Build on Windows

!!! warning
    This is only experimental.

#### Requirements

This procedure has only been tested with using a [Windows Dev Machine](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/):

- Windows 11 Enterprise
- Visual Studio 2022 Community Edition
- [Git version 2.37.3](https://github.com/git-for-windows/git/releases/download/v2.37.3.windows.1/Git-2.37.3-64-bit.exe) (to download Abseil)
- [cmake version 3.24.1](https://github.com/Kitware/CMake/releases/download/v3.24.1/cmake-3.24.1-windows-x86_64.msi)

Optional:
- [ccache v4.6.3](https://github.com/ccache/ccache/releases/download/v4.6.3/ccache-4.6.3-windows-x86_64.zip)

#### Steps

1. Configure the plugin

    ```console
    PS C:\Users\User\quokka> cmake -B build -S . -DIdaSdk_ROOT_DIR=third_party/idasdk80 -A x64
    ```

2. Perform the build

    ```console
    PS C:\Users\User\quokka> cmake --build build --target quokka_plugin --config Release
    ```

3. Cross your fingers and hope.

    `Quokka` for Windows is experimental and not tested. There are known issues with older Visual Studio versions and Ninja.
    Feel free to report any bug.

## Ghidra Extension

### Requirements

- JDK 21+
- Gradle >= 8.5 (a Gradle wrapper is included, so no system-wide install is needed)
- Ghidra >= 12.0.3

### Building

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
cd ghidra_extension
rm -rf dist/
./gradlew buildExtension
```

The extension ZIP is generated in `dist/` (e.g. `ghidra_12.0.3_PUBLIC_QuokkaExporter.zip`).

### Installing

1. Open Ghidra
2. File > Install Extensions
3. Add the ZIP file from `dist/`
4. Restart Ghidra

Alternatively, unzip the extension directly into the Ghidra extensions directory:

```bash
unzip -o ghidra_extension/dist/ghidra_*_QuokkaExporter.zip \
  -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/"
```

!!! tip
    The `scripts/fetch_ghidra.sh` script can download the correct Ghidra release
    matching the version pinned in the repository:

    ```bash
    export GHIDRA_INSTALL_DIR="$(scripts/fetch_ghidra.sh)"
    ```
