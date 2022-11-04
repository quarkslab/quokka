"""Utilities functions for the analysis"""
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

from __future__ import annotations
import networkx as nx

import quokka
from quokka.types import Union


def split_chunk(
    chunk: quokka.Chunk,
) -> Union[quokka.Chunk, quokka.SuperChunk]:
    """Split a chunk if it is composed of multiple components.

    If a chunk is composed of multiple connected components, we want to split them so
    some analysis may be performed.

    Arguments:
        chunk: A chunk to split

    Returns:
        Either a Chunk or a SuperChunk
    """
    components = list(nx.connected_components(nx.Graph(chunk.graph)))
    if len(components) <= 1:
        return chunk

    return quokka.function.SuperChunk(chunk, components)
