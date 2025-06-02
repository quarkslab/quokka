import quokka
from quokka.types import FunctionType


def test_export():
    prog: quokka.Program = quokka.Program("docs/samples/qb-crackme.quokka", "docs/samples/qb-crackme")
    assert prog is not None, "Unable to export"

    # Check number of functions
    assert len(prog.fun_names) == 49, "Missing some functions"

    for index in range(10):
        assert f"level{index}" in prog.fun_names, f"Missing function level {index}"

    # Level0
    func = prog.get_function("level0")
    assert func.start == 0x80492bc, "Wrong start"
    assert len(func.graph) == 7, "Missing block"
    assert len(func.graph.edges) == 8, "Missing edge"

    # Imports
    func = prog[0x804e04c]
    assert func.name == "strcmp", "Wrong function name"
    assert func.type == FunctionType.IMPORTED, "Wrong import type"
    assert len(func) == 1, "Wrong number of chunks"
    assert func[func.start].chunk_type == FunctionType.IMPORTED, "Wrong chunk type"
