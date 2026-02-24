import ida_name
import ida_typeinf
import ida_bytes
import ida_funcs
import ida_xref

from quokka import Program



def apply_program(program: Program) -> None:
    """Apply the program to the IDA current database."""

    til = ida_typeinf.get_idati()        

    for fun_addr, function in program.items():
        edits = function.proto.edits

        # Set name if it has been edited
        if edits.name_set:
            res = "x"
            if ida_name.set_name(fun_addr, function.name):
                res = "✓"
            print(f"[{res}] set name of function at 0x{fun_addr:x} to {function.name}")

        if edits.prototype_set:
            flg = ida_typeinf.TINFO_DEFINITE
            res = "x"
            if ida_typeinf.apply_cdecl(til, fun_addr, function.prototype, flg):
                res = "✓"
            print(f"[{res}] set prototype of function at 0x{fun_addr:x} to {function.prototype}")

        if edits.comments:
            cmts = "\n".join(function.proto.comments[x] for x in edits.comments)
            res = "x"
            if ida_funcs.set_func_cmt(fun_addr, cmts, True):  # set it repeatable
                res = "✓"
            print(f"[{res}] set comment of function at 0x{fun_addr:x}")

        if edits.edges:
            for edge in (function.proto.edges[x] for x in edits.edges):
                src_addr = function._index_to_address[edge.source]
                dst_addr = function._index_to_address[edge.destination]
                src, dst = function[src_addr], function[dst_addr]
                res = "x"
                if ida_xref.add_cref(src, dst, ida_xref.fl_USobsolete):
                    res = "✓"
                print(f"[{res}] add edge from 0x{src:x} to 0x{dst:x}")
