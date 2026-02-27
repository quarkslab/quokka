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

import os
from os.path import normpath

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):
    """Custom build_py that generates quokka_pb2.py from quokka.proto."""

    def run(self):
        self._generate_proto()
        super().run()

    def _generate_proto(self):
        from grpc_tools import protoc

        proto_dir = "proto"
        output_dir = normpath("bindings/python/quokka")
        proto_file = os.path.join(proto_dir, "quokka.proto")

        if not os.path.exists(proto_file):
            raise FileNotFoundError(
                f"Proto file not found: {proto_file}. "
                "Ensure the sdist includes the proto/ directory."
            )

        print(f"Generating {output_dir}/quokka_pb2.py from {proto_file}")
        exit_code = protoc.main([
            "grpc_tools.protoc",
            f"--proto_path={proto_dir}",
            f"--python_out={output_dir}",
            proto_file,
        ])
        if exit_code != 0:
            raise RuntimeError(f"protoc failed with exit code {exit_code}")


main_ns = {}
ver_path = normpath("bindings/python/quokka/version.py")
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(
    version=main_ns["__version__"],
    cmdclass={"build_py": build_py},
)
