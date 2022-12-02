# -*- coding: utf-8 -*-

#  Copyright 2022 Quarkslab
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from setuptools import setup

with open("README.md", "r") as fd:
    readme = fd.read()

setup(
    name="quokka-project",
    version="1.0.5",
    author="Alexis <dm> Challande",
    author_email="achallande@quarkslab.com",
    url="https://github.com/quarkslab/quokka",
    project_urls={
        "Documentation": "https://quarkslab.github.io/quokka/",
        "Bug Tracker": "https://github.com/quarkslab/quokka/issues",
        "Source": "https://github.com/quarkslab/quokka/",
    },
    description="Quokka : A Fast and Accurate Binary Exporter",
    long_description=readme,
    long_description_content_type="text/markdown",
    packages=["quokka", "quokka.analysis", "quokka.backends"],
    package_dir={"": "bindings/python/"},
    package_data={"quokka": ["*.pyi", "*.typed"]},
    setup_requires=[
        "protobuf_distutils",
    ],
    license="Apache-2",
    options={
        "generate_py_protobufs": {
            "source_dir": "proto",
            "output_dir": "bindings/python/quokka",
        },
    },
    install_requires=[
        "capstone>=4.0.2,<5",
        "networkx>=2.4,<3",
        "protobuf>=3.12.2,<4",
        "pypcode>=1.1.1,<2",
    ],
    extras_require={
        "test": [
            "pytest",
            "pytest-mock",
            "pytest-cov",
            "coverage[toml]",
        ],
        "doc": [
            "mkdocs",
            "mkdocs-material",
            "mkdocstrings",
            "mkdocstrings-python",
            "mkdocs-literate-nav",
            "mkdocs-git-revision-date-localized-plugin",
            "mkdocs-gen-files",
            "mkdocs-simple-hooks",
        ],
        "dev": [
            "black",
            "ipython",
            "flake8",
            "flake8-black",
            "mypy",
            "mypy-protobuf",
            "nox",
        ],
    },
)
