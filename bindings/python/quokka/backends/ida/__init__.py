from datetime import datetime
import ida_name
import ida_typeinf
import ida_bytes
import ida_funcs
import ida_xref
import ida_loader
import ida_kernwin
from quokka import Program, Function, Data

def do_snapshot():
    snap = ida_loader.snapshot_t()
    snap.desc = datetime.now().strftime("quokka_snapshot_%Y-%m-%d_%H-%M-%S")
    ok, err = ida_kernwin.take_database_snapshot(snap)
    if ok:
        print("Snapshot created:", snap.filename)
    else:
        print("Snapshot failed:", err)


def apply_quokka(program: Program) -> int:
    """Apply the program to the IDA current database.
    
    Returns:
        The number of errors encountered while applying the changes.
    """      
    errors_count = 0

    # Take a snapshot before applying the changes, so we can easily revert if something goes wrong.
    do_snapshot()

    # First apply types, as functions and data may depend on them.
    errors_count += apply_types(program)

    # Iterate functions for edits to apply
    for function in program.functions:
        edits = function.proto.edits
        if edits.name_set or edits.prototype_set or edits.comments:
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
            res = "ok"
        else:
            errors_count += 1
        print(f"[{res}] set name of function at 0x{fun_addr:x} to {function.name}")

    if edits.prototype_set:
        flg = ida_typeinf.TINFO_DEFINITE
        res = "x"
        if ida_typeinf.apply_cdecl(til, fun_addr, function.prototype, flg):
            res = "ok"
        else:
            errors_count += 1
        print(f"[{res}] set prototype of function at 0x{fun_addr:x} to {function.prototype}")

    if edits.comments:
        cmts = "\n".join(function.proto.comments[x] for x in edits.comments)
        res = "x"
        if ida_funcs.set_func_cmt(fun_addr, cmts, True):  # set it repeatable
            res = "ok"
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
                res = "ok"
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
            res = "ok"
        else:
            errors_count += 1
        print(f"[{res}] set name of data at 0x{data.address:x} to {data.name}")

    if edits.type_str:
        res = "x"
        if ida_typeinf.apply_cdecl(til, data.address, edits.type_str, ida_typeinf.TINFO_DEFINITE):
            res = "ok"
        else:
            errors_count += 1
        print(f"[{res}] set type of data at 0x{data.address:x} to {edits.type_str}")

    if edits.comments:
        cmts = "\n".join(data.proto.comments[x] for x in edits.comments)
        res = "x"
        if ida_bytes.set_cmt(data.address, cmts, True):  # set it repeatable
            res = "ok"
        else:
            errors_count += 1
        print(f"[{res}] set comment of data at 0x{data.address:x}")

    return errors_count


def apply_types(program: Program) -> int:
    """Apply new user-defined types to the IDA database.

    Only types with ``is_new == True`` are created.  All types are registered
    into the current TIL via ``parse_decls`` using their ``c_str`` (C
    declaration).

    Iterates proto types directly because ``program.types`` filters out
    ``is_new`` entries.

    Returns:
        The number of errors encountered.
    """
    errors_count = 0

    for pb_type in program.proto.types:
        if not pb_type.is_new:
            continue

        oneof = pb_type.WhichOneof("OneofType")
        if oneof == "composite_type":
            ct = pb_type.composite_type
        elif oneof == "enum_type":
            ct = pb_type.enum_type
        else:
            continue

        errors_count += _apply_type(ct.c_str, ct.name)

    return errors_count


def _apply_type(c_str: str, name: str) -> int:
    """Register a single new type into the current TIL via ``parse_decls``.

    Returns:
        The error count (0 or 1).
    """
    if not c_str:
        print(f"[x] create type {name} (no c_str available)")
        return 1

    til = ida_typeinf.get_idati()
    if ida_typeinf.parse_decls(til, c_str, None, ida_typeinf.HTI_DCL) == 0:
        print(f"[ok] create type {name}")
        return 0

    print(f"[x] create type {name}")
    return 1


