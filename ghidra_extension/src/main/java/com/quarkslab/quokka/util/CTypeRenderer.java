package com.quarkslab.quokka.util;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

/**
 * Renders individual Ghidra DataTypes as C declarations.
 *
 * Produces per-type C strings for the proto {@code c_str} field, following
 * the output patterns of Ghidra's {@code DataTypeWriter} without its
 * bulk-export and dependency-expansion behavior.
 */
public final class CTypeRenderer {

    private CTypeRenderer() {}

    /**
     * Render a single DataType as its C declaration string.
     *
     * @return C declaration, or null for types that have no standalone declaration
     *         (primitives, function definitions)
     */
    public static String render(DataType dt) {
        if (dt instanceof ghidra.program.model.data.Enum)
            return renderEnum((ghidra.program.model.data.Enum) dt);
        if (dt instanceof Structure)
            return renderStruct((Structure) dt);
        if (dt instanceof Union)
            return renderUnion((Union) dt);
        if (dt instanceof TypeDef)
            return renderTypedef((TypeDef) dt);
        if (dt instanceof Pointer)
            return renderPointer((Pointer) dt);
        if (dt instanceof Array)
            return renderArray((Array) dt);
        return null;
    }

    private static String renderEnum(ghidra.program.model.data.Enum e) {
        StringBuilder sb = new StringBuilder();
        sb.append("typedef enum ").append(e.getDisplayName()).append(" {\n");
        String[] names = e.getNames();
        for (int i = 0; i < names.length; i++) {
            sb.append("    ").append(names[i])
              .append(" = ").append(e.getValue(names[i]));
            if (i < names.length - 1) sb.append(',');
            sb.append('\n');
        }
        sb.append("} ").append(e.getDisplayName()).append(';');
        return sb.toString();
    }

    private static String renderStruct(Structure s) {
        return renderComposite(s, "struct");
    }

    private static String renderUnion(Union u) {
        return renderComposite(u, "union");
    }

    private static String renderComposite(Composite c, String keyword) {
        StringBuilder sb = new StringBuilder();
        sb.append(keyword).append(' ').append(c.getDisplayName()).append(" {\n");

        boolean isUnion = c instanceof Union;
        DataTypeComponent[] components = isUnion
                ? ((Union) c).getComponents()
                : ((Structure) c).getDefinedComponents();

        for (DataTypeComponent comp : components) {
            sb.append("    ");
            String fieldName = comp.getFieldName();
            if (fieldName == null || fieldName.isEmpty())
                fieldName = comp.getDefaultFieldName();
            if (fieldName == null) fieldName = "";

            sb.append(fieldDecl(fieldName, comp.getDataType()));
            sb.append(";\n");
        }
        sb.append("};");
        return sb.toString();
    }

    private static String renderTypedef(TypeDef td) {
        return "typedef " + fieldDecl(td.getDisplayName(), td.getDataType()) + ";";
    }

    private static String renderPointer(Pointer p) {
        return p.getDisplayName();
    }

    private static String renderArray(Array a) {
        return a.getDisplayName();
    }

    // ------------------------------------------------------------------
    // Field declaration helpers
    // ------------------------------------------------------------------

    /**
     * Build a C field declaration, handling pointer/array nesting,
     * bitfields, and function pointers.
     *
     * <p>Package-private for testing.
     */
    static String fieldDecl(String name, DataType dt) {
        // Bitfields: baseType name : bits
        if (dt instanceof BitFieldDataType) {
            BitFieldDataType bf = (BitFieldDataType) dt;
            DataType baseType = bf.getBaseDataType();
            return baseType.getDisplayName() + " " + name + " : " + bf.getBitSize();
        }

        // Unwrap pointer/array layers, building name decorations
        while (true) {
            if (dt instanceof Array) {
                name = name + "[" + ((Array) dt).getNumElements() + "]";
                dt = ((Array) dt).getDataType();
            } else if (dt instanceof Pointer) {
                DataType inner = ((Pointer) dt).getDataType();
                if (inner == null) {
                    // void pointer
                    name = "*" + name;
                    return "void " + name;
                }
                if (inner instanceof FunctionDefinition) {
                    return funcPtrDecl(name, (FunctionDefinition) inner);
                }
                name = "*" + name;
                if (inner instanceof Array) name = "(" + name + ")";
                dt = inner;
            } else {
                break;
            }
        }

        return typePrefix(dt) + dt.getDisplayName() + " " + name;
    }

    /**
     * Render a function pointer field declaration:
     * {@code returnType (*decoratedName)(params)}
     */
    private static String funcPtrDecl(String decoratedName, FunctionDefinition fd) {
        StringBuilder sb = new StringBuilder();

        DataType retType = fd.getReturnType();
        if (retType != null) {
            sb.append(typePrefix(retType)).append(retType.getDisplayName());
        } else {
            sb.append("void");
        }

        sb.append(" (*").append(decoratedName).append(")(");

        ParameterDefinition[] params = fd.getArguments();
        if (params.length == 0) {
            sb.append("void");
        } else {
            for (int i = 0; i < params.length; i++) {
                if (i > 0) sb.append(", ");
                DataType pType = params[i].getDataType();
                sb.append(typePrefix(pType)).append(pType.getDisplayName());
                String pName = params[i].getName();
                if (pName != null && !pName.isEmpty()) {
                    sb.append(' ').append(pName);
                }
            }
        }

        sb.append(')');
        return sb.toString();
    }

    /**
     * Return the C keyword prefix for composite/enum types.
     */
    private static String typePrefix(DataType dt) {
        if (dt instanceof Structure) return "struct ";
        if (dt instanceof Union)     return "union ";
        if (dt instanceof ghidra.program.model.data.Enum) return "enum ";
        return "";
    }
}
