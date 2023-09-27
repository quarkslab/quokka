# -*- coding: utf-8 -*-

#  Copyright 2022-2023 Quarkslab
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
from os.path import normpath

main_ns = {}
ver_path = normpath("bindings/python/quokka/version.py")
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(
    version=main_ns["__version__"],
    options={
        "generate_py_protobufs": {
            "source_dir": "proto",
            "output_dir": "bindings/python/quokka",
        },
    },
)
