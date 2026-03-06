package com.quarkslab.quokka.util;

import ghidra.program.model.listing.Function;
import quokka.QuokkaOuterClass.Quokka;

/**
 * Maps Ghidra function properties to proto Function.FunctionType.
 * Order matters: thunk check first, then external, then library, then normal.
 */
public final class FunctionTypeMapper {

    private FunctionTypeMapper() {}

    public static Quokka.Function.FunctionType map(Function function) {
        if (function.isThunk()) {
            return Quokka.Function.FunctionType.TYPE_THUNK;
        }
        if (function.isExternal()) {
            return Quokka.Function.FunctionType.TYPE_IMPORTED;
        }
        // Ghidra doesn't have a direct FUNC_LIB flag like IDA.
        // Functions identified as library code by FID or signature matching
        // are not trivially detectable; default to NORMAL.
        return Quokka.Function.FunctionType.TYPE_NORMAL;
    }
}
