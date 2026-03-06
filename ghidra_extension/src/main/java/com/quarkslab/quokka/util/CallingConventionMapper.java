package com.quarkslab.quokka.util;

import quokka.QuokkaOuterClass.Quokka;

/**
 * Maps Ghidra calling convention name strings to proto CallingConvention values.
 * Ghidra CC names come from program.getCompilerSpec().getDefaultCallingConvention().getName().
 */
public final class CallingConventionMapper {

    private CallingConventionMapper() {}

    public static Quokka.CallingConvention map(String ccName) {
        if (ccName == null || ccName.isEmpty()) {
            return Quokka.CallingConvention.CC_UNK;
        }
        switch (ccName) {
            case "__cdecl":
                return Quokka.CallingConvention.CC_CDECL;
            case "__stdcall":
                return Quokka.CallingConvention.CC_STDCALL;
            case "__fastcall":
                return Quokka.CallingConvention.CC_FASTCALL;
            case "__thiscall":
                return Quokka.CallingConvention.CC_THISCALL;
            case "__pascal":
                return Quokka.CallingConvention.CC_PASCAL;
            case "__ellipsis":
                return Quokka.CallingConvention.CC_ELLIPSIS;
            case "__swiftcall":
                return Quokka.CallingConvention.CC_SWIFT;
            case "__golang":
                return Quokka.CallingConvention.CC_GOLANG;
            default:
                return Quokka.CallingConvention.CC_UNK;
        }
    }
}
