package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.util.GhidraTypeMapper;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import quokka.QuokkaOuterClass.Quokka;

import java.util.*;

/**
 * Phase 3: Export Type[] with the pinned invariant:
 *   indices 0-8 = primitives (BaseType enum order)
 *   9..N        = enums (sorted by name)
 *   N+1..M      = composites (sorted by name, then kind)
 */
public class TypeExporter {

    private TypeExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder) {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // Step 1: Write 9 primitive types (indices 0-8, always)
        for (int i = 0; i <= 8; i++) {
            Quokka.BaseType bt = Quokka.BaseType.forNumber(i);
            builder.addTypes(Quokka.Type.newBuilder().setPrimitiveType(bt));
        }

        // Step 2: Collect enums and composites from DataTypeManager
        List<ghidra.program.model.data.Enum> enums = new ArrayList<>();
        List<DataType> composites = new ArrayList<>(); // Struct, Union, Pointer, Array

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (dt instanceof ghidra.program.model.data.Enum) {
                enums.add((ghidra.program.model.data.Enum) dt);
            } else if (dt instanceof Structure || dt instanceof Union) {
                composites.add(dt);
            }
            // Note: Pointer and Array types referenced by data/functions will be
            // added on-demand during composite member resolution
        }

        // Step 3: Sort enums by name, write them (indices 9..N)
        enums.sort(Comparator.comparing(DataType::getName));
        for (ghidra.program.model.data.Enum enumDt : enums) {
            ctx.registerEnumType(enumDt.getName());

            Quokka.EnumType.Builder enumBuilder = Quokka.EnumType.newBuilder()
                    .setName(enumDt.getName());

            // Add enum values
            for (String valueName : enumDt.getNames()) {
                enumBuilder.addValues(Quokka.EnumType.EnumValue.newBuilder()
                        .setName(valueName)
                        .setValue(enumDt.getValue(valueName)));
            }

            // Base type from underlying integer size
            Quokka.BaseType baseType = GhidraTypeMapper.mapBySize(enumDt.getLength());
            enumBuilder.setBaseType(GhidraTypeMapper.baseTypeIndex(baseType));

            // C declaration string
            String cStr = enumDt.toString();
            if (cStr != null && !cStr.isEmpty()) {
                enumBuilder.setCStr(cStr);
            }

            builder.addTypes(Quokka.Type.newBuilder().setEnumType(enumBuilder));
        }

        // Step 4: Sort composites by (name, then struct before union)
        composites.sort(Comparator.comparing(DataType::getName)
                .thenComparing(dt -> dt instanceof Union ? 1 : 0));

        // First pass: register all composite types (for forward references)
        List<Quokka.CompositeType.Builder> compositeBuilders = new ArrayList<>();
        for (DataType dt : composites) {
            String kind = dt instanceof Union ? "UNION" : "STRUCT";
            ctx.registerCompositeType(dt.getName() + ":" + kind);

            Quokka.CompositeType.Builder cb = Quokka.CompositeType.newBuilder()
                    .setName(dt.getName())
                    .setType(dt instanceof Union
                            ? Quokka.CompositeType.CompositeSubType.TYPE_UNION
                            : Quokka.CompositeType.CompositeSubType.TYPE_STRUCT)
                    .setSize(dt.getLength());

            String cStr = dt.toString();
            if (cStr != null && !cStr.isEmpty()) {
                cb.setCStr(cStr);
            }

            compositeBuilders.add(cb);
        }

        // Second pass: fill members (now all types are registered for index resolution)
        for (int i = 0; i < composites.size(); i++) {
            DataType dt = composites.get(i);
            Quokka.CompositeType.Builder cb = compositeBuilders.get(i);
            fillMembers(ctx, dt, cb);
        }

        // Add all composites to proto
        for (Quokka.CompositeType.Builder cb : compositeBuilders) {
            builder.addTypes(Quokka.Type.newBuilder().setCompositeType(cb));
        }
    }

    private static void fillMembers(ExportContext ctx, DataType dt,
            Quokka.CompositeType.Builder cb) {
        DataTypeComponent[] components;
        if (dt instanceof Structure) {
            components = ((Structure) dt).getDefinedComponents();
        } else if (dt instanceof Union) {
            components = ((Union) dt).getComponents();
        } else {
            return;
        }

        for (DataTypeComponent comp : components) {
            Quokka.CompositeType.Member.Builder member =
                    Quokka.CompositeType.Member.newBuilder();

            // Offset in bits (for structs: byte offset * 8, for unions: 0)
            if (dt instanceof Union) {
                member.setOffset(0);
            } else {
                member.setOffset(comp.getOffset() * 8);
            }

            String memberName = comp.getFieldName();
            if (memberName == null || memberName.isEmpty()) {
                memberName = comp.getDefaultFieldName();
            }
            member.setName(memberName != null ? memberName : "");

            // Resolve member type index
            member.setTypeIndex(ctx.resolveTypeIndex(comp.getDataType()));

            // Size in bits
            member.setSize(comp.getLength() * 8);

            cb.addMembers(member);
        }
    }
}
