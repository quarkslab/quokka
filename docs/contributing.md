# Development - Contributing

## Developing

Clone the repository and install it in a `virtualenv` in an editable mode with
the developers dependencies.

```commandline
$ python -m venv env
$ source ./env/bin/activate
$ cd quokka
(env) $ pip install -e '.[dev]'
(env) $ python -c "import quokka; print(quokka.__version__)"
```

## Format the code

The project uses the [`black`](https://github.com/psf/black) formatter for the
Python code with the **defaults** settings.

!!! example "Running Black"
	```commandline
	(env) $ black bindings/python/
	```

The C++ code is formatted using `clang-format`.

## Updating the Protobuf definition

To update the Protobuf definition, follow these steps:

1. <!> IMPORTANT <!> Open an issue on the official repository
2. Update the `proto/quokka.proto` file with the new fields
3. Increase the version number in `CMakeLists.txt` by:
   - A major version if the change breaks backward compatibility
   - A minor version otherwise
4. Write the exporter code (IDA and/or Ghidra)
5. Update the python bindings accordingly
6. Update the `__version__` in `bindings/python/quokka/version.py` to match
   the one in step 3.
7. Regenerate the protobuf Python bindings by reinstalling:
   `pip install -e .`

## Add a new IDA Version / SDK

### Add an image with the new IDA Version

For example, using `Version 7.7`:

1. Go to `ci`
1. Copy installer to `ci/ida77/ida.run`
1. (Optional) Copy `~/.idapro/ida.reg` to `ci/ida77/ida.reg`
1. (Optional) Add the installation password in a file to remember it for next time
1. Build the image
	```console
	$ docker build --file build.dockerfile \
	         --build-arg IDA_DIRECTORY=ida77 \
	         --build-arg IDA_PASSWORD=<install password> \
	         .
	```
1. (Optional). If you did not copy a `ida.reg` file, you should run the
   container first, open IDA (`/opt/ida/idat64`), accept the license and
   **save** the container (using `docker commit`).

### Add the SDK in the repo

For IDA >= 9.2, the SDK is [open source](https://github.com/HexRaysSA/ida-sdk)
and fetched automatically by CMake via `-DIDA_VERSION=<major>.<minor>`.


## Other tips and tricks

Read the [Dev's Tips & Tricks](dev.md) page!
