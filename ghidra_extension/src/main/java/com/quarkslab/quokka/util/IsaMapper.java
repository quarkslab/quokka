package com.quarkslab.quokka.util;

import quokka.QuokkaOuterClass.Quokka;

/**
 * Maps Ghidra processor names to proto ISA enum values.
 * Ghidra processor names come from program.getLanguage().getProcessor().toString().
 */
public final class IsaMapper {

    private IsaMapper() {}

    public static Quokka.Meta.ISA map(String processorName) {
        if (processorName == null) {
            return Quokka.Meta.ISA.PROC_UNK;
        }
        switch (processorName) {
            case "x86":
                return Quokka.Meta.ISA.PROC_INTEL;
            case "ARM":
            case "AARCH64":
                return Quokka.Meta.ISA.PROC_ARM;
            case "MIPS":
                return Quokka.Meta.ISA.PROC_MIPS;
            case "PowerPC":
                return Quokka.Meta.ISA.PROC_PPC;
            case "Dalvik":
                return Quokka.Meta.ISA.PROC_DALVIK;
            default:
                return Quokka.Meta.ISA.PROC_UNK;
        }
    }
}
