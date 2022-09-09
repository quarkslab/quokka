# Installation

## Python Bindings

### System requirements

- python 3.9 is required. It should also work with higher versions and is
  regularly developed with python 3.10.

!!! note
    While the IDA plugin requires Linux, the Python bindings should also 
    work on other architectures. However, it has not yet been tested.


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

### Requirements

## IDA Plugin

!!! warning
    The plugin support for **Windows** is experimental.

### From the CI

The plugin is built on the CI and available in the
[Release](https://github.com/quarkslab/quokka/releases/new).

To download the plugin, get the file named `quokka_plugin**.so`.

### Building

#### Requirements :

- CMake (at least 3.13)
- A reasonable modern compiler supporting at least Cxx17
- IDA Sdk (version 7.7) 64 bits
- IDA (7.7 and higher)

#### Standard build

The first step is to download the sources. You can clone the repository like in [here](#using-the-sources)


To compile `quokka`, you first need to generate the configuration using `CMake`.

```console
user@host:~$ cd quokka
user@host:~/quokka$ cmake -B build \ # Where to build 
                          -S . \ # Where are the sources
                          -DIdaSdk_ROOT_DIR:STRING=path/to/ida_sdk \ # Path to IDA SDK 
                          -DCMAKE_BUILD_TYPE:STRING=Release # Build Type
```

If the first step succeeded, you can now do the actual building.

```console
user@host:~/quokka$ cmake --build build --target quokka_plugin -- -j  # use as many core as possible
```

### Build On Windows

!!! warning

    This is only experimental.

#### Requirements

This procedure has only been tested with using a [Windows Dev Machine](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/):

- Windows 11 Entreprise
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
