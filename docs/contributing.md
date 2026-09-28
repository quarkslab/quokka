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

- Python: [`black`](https://github.com/psf/black) with default settings, linted by `flake8` (both in the `dev` extra): `black bindings/python/`
- C++: `clang-format` (`.clang-format` at the repository root)

## Updating the Protobuf definition

1. <!> IMPORTANT <!> Open an issue on the official repository
2. Update `proto/quokka.proto`: never renumber or reuse field numbers; prefer additive changes
3. Bump the version -- major if the change breaks backward compatibility, minor otherwise -- in
   `CMakeLists.txt`, `bindings/python/quokka/version.py`, `ghidra_extension/build.gradle`,
   `binaryninja_extension/bn_quokka/version.py` + `plugin.json`, and `ida-plugin.json`
4. Update every exporter (IDA, Ghidra, Binary Ninja) and the Python bindings
5. Regenerate the generated code: `pip install -e .` (Python) and
   `python binaryninja_extension/generate_proto.py` (Binary Ninja, committed module)

## Add a new IDA Version / SDK

### Add an image with the new IDA Version

!!! warning
    The `ci/` Dockerfiles are not used by the current CI workflows (see the roadmap, R-CI-3).

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
