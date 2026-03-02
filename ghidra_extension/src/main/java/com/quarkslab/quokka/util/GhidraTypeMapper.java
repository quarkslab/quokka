package com.quarkslab.quokka.util;

import ghidra.program.model.data.*;
import quokka.QuokkaOuterClass.Quokka;

/**
 * Maps Ghidra DataType to proto type indices and BaseType enum values.
 * Primitive types map to indices 0-8 (pinned by proto contract).
 */
public final class GhidraTypeMapper {

    private GhidraTypeMapper() {}

    /**
     * Map a Ghidra DataType to a proto BaseType value for primitive types.
     * Returns null if the type is not a recognizable primitive.
     */
    public static Quokka.BaseType mapPrimitive(DataType dt) {
        if (dt instanceof VoidDataType) {
            return Quokka.BaseType.TYPE_VOID;
        }
        if (dt instanceof AbstractFloatDataType) {
            if (dt instanceof FloatDataType || dt.getLength() == 4) {
                return Quokka.BaseType.TYPE_FLOAT;
            }
            if (dt instanceof DoubleDataType || dt.getLength() == 8) {
                return Quokka.BaseType.TYPE_DOUBLE;
            }
        }
        if (dt instanceof AbstractIntegerDataType || dt instanceof Undefined) {
            return mapBySize(dt.getLength());
        }
        if (dt instanceof BooleanDataType) {
            return Quokka.BaseType.TYPE_B;
        }
        if (dt instanceof CharDataType || dt instanceof WideCharDataType
                || dt instanceof WideChar16DataType || dt instanceof WideChar32DataType) {
            return mapBySize(dt.getLength());
        }
        return null;
    }

    /**
     * Map an integer/undefined type by its byte size to a proto BaseType.
     */
    public static Quokka.BaseType mapBySize(int byteSize) {
        switch (byteSize) {
            case 1: return Quokka.BaseType.TYPE_B;
            case 2: return Quokka.BaseType.TYPE_W;
            case 4: return Quokka.BaseType.TYPE_DW;
            case 8: return Quokka.BaseType.TYPE_QW;
            case 16: return Quokka.BaseType.TYPE_OW;
            default: return Quokka.BaseType.TYPE_UNK;
        }
    }

    /**
     * Return the proto type index for a BaseType.
     * Indices 0-8 are pinned primitives matching the BaseType enum order.
     */
    public static int baseTypeIndex(Quokka.BaseType bt) {
        return bt.getNumber();
    }
}
