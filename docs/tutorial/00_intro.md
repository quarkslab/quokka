# Tutorial

This tutorial show some usage __Quokka__ Python API.

## Run the code

!!! info
    All the code snippets are valid Python / Bash snippet and may be run directly.

I suggest installing [IPython](http://ipython.org/) for an interactive Python terminal with syntax highlighting and
auto-completion

## Step 1: Install quokka

!!! tip
    It's best to install quokka in a [virtualenv](https://virtualenv.pypa.io/en/latest/).

```commandline
$ pip install pip install git+https://github.com/quarkslab/quokka.git
```

## Step 2: Download the binaries for the tutorial

For this tutorial, we will use a simple CrackMe.
You can download it [here](https://github.com/quarkslab/quokka/blob/main/docs/samples/qb-crackme).
If you don't have IDA, you will also need the exported file: [here](https://github.com/quarkslab/quokka/blob/main/docs/samples/qb-crackme.qk).

## Check

Let's now check that `quokka` has been installed!

```commandline
$ python -c "import quokka"
```

If the result is not the following (or any other errors), congrats!
```shell
Traceback (most recent call last):
  File "<string>", line 1, in <module>
ModuleNotFoundError: No module named 'quokka'
```