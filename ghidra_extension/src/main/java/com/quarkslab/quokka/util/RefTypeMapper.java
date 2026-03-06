package com.quarkslab.quokka.util;

import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import quokka.QuokkaOuterClass.Quokka;

/**
 * Maps Ghidra RefType constants to proto EdgeType values.
 * Reference: proto/quokka.proto EdgeType comments specify the Ghidra mapping.
 */
public final class RefTypeMapper {

    private RefTypeMapper() {}

    public static Quokka.EdgeType map(RefType refType) {
        if (refType == null) {
            return Quokka.EdgeType.EDGE_UNKNOWN;
        }

        // Flow types (jumps and calls)
        if (refType == RefType.UNCONDITIONAL_JUMP
                || refType == RefType.JUMP_OVERRIDE_UNCONDITIONAL) {
            return Quokka.EdgeType.EDGE_JUMP_UNCOND;
        }
        if (refType == RefType.CONDITIONAL_JUMP) {
            return Quokka.EdgeType.EDGE_JUMP_COND;
        }
        if (refType == RefType.COMPUTED_JUMP
                || refType == RefType.CONDITIONAL_COMPUTED_JUMP) {
            return Quokka.EdgeType.EDGE_JUMP_INDIR;
        }
        if (refType == RefType.UNCONDITIONAL_CALL
                || refType == RefType.CONDITIONAL_CALL
                || refType == RefType.CALL_TERMINATOR
                || refType == RefType.CONDITIONAL_CALL_TERMINATOR
                || refType == RefType.CALL_OVERRIDE_UNCONDITIONAL
                || refType == RefType.CALLOTHER_OVERRIDE_CALL) {
            return Quokka.EdgeType.EDGE_CALL;
        }
        if (refType == RefType.COMPUTED_CALL
                || refType == RefType.CONDITIONAL_COMPUTED_CALL
                || refType == RefType.COMPUTED_CALL_TERMINATOR) {
            return Quokka.EdgeType.EDGE_CALL_INDIR;
        }

        // Data reference types
        if (refType == RefType.READ || refType == RefType.READ_WRITE) {
            return Quokka.EdgeType.EDGE_DATA_READ;
        }
        if (refType == RefType.WRITE) {
            return Quokka.EdgeType.EDGE_DATA_WRITE;
        }
        if (refType == RefType.DATA
                || refType == RefType.DATA_IND
                || refType == RefType.READ_IND
                || refType == RefType.WRITE_IND
                || refType == RefType.READ_WRITE_IND
                || refType == RefType.PARAM
                || refType == RefType.EXTERNAL_REF) {
            return Quokka.EdgeType.EDGE_DATA_INDIR;
        }

        return Quokka.EdgeType.EDGE_UNKNOWN;
    }
}
