package com.quarkslab.quokka.utils;

import java.math.BigInteger;
import ghidra.program.model.data.ByteDataType;
import quokka.QuokkaOuterClass.Quokka.DataType;


/**
 * Collection of utility functions. Only static methods
 */
public class Utils {
    private Utils() {}

    /**
     * Parse a ghidra data type and returns the corresponding quokka protobuf data type
     * 
     * @param ghidraDataType The input ghidra data type
     * @return The quokka protobuf data type
     */
    public static DataType getDataTypeFromGhidra(
            ghidra.program.model.data.DataType ghidraDataType) {
        // TODO replace with pattern matching for switch.
        // The feature shouldn't be considered anymore as preview starting from java 21
        // https://openjdk.org/jeps/441
        // TODO implement all the possible data types
        // https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html
        if (ghidraDataType instanceof ByteDataType) {
            return DataType.TYPE_B;
        }

        return DataType.TYPE_UNK;
    }
}
