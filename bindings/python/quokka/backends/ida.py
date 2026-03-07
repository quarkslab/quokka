import ida_name
import ida_typeinf
import ida_bytes
import ida_funcs
import ida_xref

from quokka import Program, Function, Data
from quokka.data_type import ComplexType



def apply_quokka(program: Program) -> int:
    """Apply the program to the IDA current database.
    
    Returns:
        The number of errors encountered while applying the changes.
    """      
    errors_count = 0

    # First apply types, as functions and data may depend on them.
    errors_count += apply_types(program)

    # Iterate functions for edits to apply
    for function in program.functions:
        edits = function.proto.edits
        if edits.name_set or edits.type_str or edits.comments:
            errors_count += apply_function(function)

    # Iterate data for edits to apply
    for data in program.data:
        edits = data.proto.edits
        if edits.name_set or edits.type_str or edits.comments:
            errors_count += apply_data(data)

    # Invalidate Hex-Rays decompiler cache so a subsequent re-export
    # picks up the changes we just applied (names, prototypes, etc.).
    try:
        import ida_hexrays
        ida_hexrays.clear_cached_cfuncs()
    except (ImportError, AttributeError):
        pass  # Hex-Rays not available -- nothing to invalidate

    return errors_count


def apply_function(function: Function) -> int:
    fun_addr = function.address
    edits = function.proto.edits
    errors_count = 0
    til = ida_typeinf.get_idati()

    # Set name if it has been edited
    if edits.name_set:
        res = "x"
        if ida_name.set_name(fun_addr, function.name):
            res = "✓"
        else:
            errors_count += 1
        print(f"[{res}] set name of function at 0x{fun_addr:x} to {function.name}")

    if edits.prototype_set:
        flg = ida_typeinf.TINFO_DEFINITE
        res = "x"
        if ida_typeinf.apply_cdecl(til, fun_addr, function.prototype, flg):
            res = "✓"
        else:
            errors_count += 1
        print(f"[{res}] set prototype of function at 0x{fun_addr:x} to {function.prototype}")

    if edits.comments:
        cmts = "\n".join(function.proto.comments[x] for x in edits.comments)
        res = "x"
        if ida_funcs.set_func_cmt(fun_addr, cmts, True):  # set it repeatable
            res = "✓"
        else:
            errors_count += 1
        print(f"[{res}] set comment of function at 0x{fun_addr:x}")

    if edits.edges:
        for edge in (function.proto.edges[x] for x in edits.edges):
            src_addr = function._index_to_address[edge.source]
            dst_addr = function._index_to_address[edge.destination]
            src, dst = function[src_addr], function[dst_addr]
            res = "x"
            if ida_xref.add_cref(src, dst, ida_xref.fl_USobsolete):
                res = "✓"
            else:
                errors_count += 1
            print(f"[{res}] add edge from 0x{src:x} to 0x{dst:x}")
    return errors_count


def apply_data(data: Data) -> int:
    edits = data.proto.edits
    errors_count = 0
    til = ida_typeinf.get_idati()

    # Set name if it has been edited
    if edits.name_set:
        res = "x"
        if ida_name.set_name(data.address, data.name):
            res = "✓"
        else:
            errors_count += 1
        print(f"[{res}] set name of data at 0x{data.address:x} to {data.name}")

    if edits.type_str:
        res = "x"
        if ida_typeinf.apply_cdecl(til, data.address, edits.type_str, ida_typeinf.TINFO_DEFINITE):
            res = "✓"
        else:
            errors_count += 1
        print(f"[{res}] set type of data at 0x{data.address:x} to {edits.type_str}")

    if edits.comments:
        cmts = "\n".join(data.proto.comments[x] for x in edits.comments)
        res = "x"
        if ida_bytes.set_cmt(data.address, cmts, True):  # set it repeatable
            res = "✓"
        else:
            errors_count += 1
        print(f"[{res}] set comment of data at 0x{data.address:x}")

    return errors_count


def apply_types(program: Program) -> int:
    """Apply new user-defined types to the IDA database.

    Only types with ``is_new == True`` are created.  All types are registered
    into the current TIL via ``parse_decls`` using their ``c_str`` (C
    declaration).

    Returns:
        The number of errors encountered.
    """
    errors_count = 0

    for typ in program.types:
        if not isinstance(typ, ComplexType) or not typ.is_new:
            continue

        errors_count += _apply_type(typ)

    return errors_count


def _apply_type(typ: ComplexType) -> int:
    """Register a single new type into the current TIL via ``parse_decls``.

    Requires a non-empty ``c_str`` on the type.

    Returns:
        The error count (0 or 1).
    """
    kind = type(typ).__name__

    if not typ.c_str:
        print(f"[x] create {kind} {typ.name} (no c_str available)")
        return 1

    til = ida_typeinf.get_idati()
    if ida_typeinf.parse_decls(til, typ.c_str, None, ida_typeinf.HTI_DCL) == 0:
        print(f"[✓] create {kind} {typ.name}")
        return 0

    print(f"[x] create {kind} {typ.name}")
    return 1