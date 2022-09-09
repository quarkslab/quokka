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

The project use the [`black`](https://github.com/psf/black) formatter for the 
Python code with the **defaults** settings.

!!! example "Running Black"
	```commandline
	(env) $ black bindings/python/
	```

The C++ code is formatted using `clang-format`.

## Updating the Protobuf definition

To update the Protobuf definition, follow this steps:

1. <!> IMPORTANT <!> Open an issue on the official repository
2. Update the `proto/quokka.proto` file with the new fields
3. Increase the version number in `CMakeLists.txt` by :
   - A major version if the change breaks backward compatibility
   - A minor version otherwise
4. Write the exporter code
5. Update the python bindings accordingly
6. Update the `__quokka_version__` in `bindings/python/__init__.py` to match 
   the one in step 3.
7. Update the protobuf generated files for python using:
   `python setup.py generate_py_protobufs`

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

1. Download the SDK from HexRays website
2. Extract it
3. Generate a password for the SDK archive.
4. Compress the inner `idasdk77/` directory in an archive protected by the
   password.
5. Add the `idasdk77.zip` to the repository.


## Other tips and tricks

Read the [Dev's Tips & Tricks](dev.md) page!