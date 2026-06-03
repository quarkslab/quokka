package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.util.CTypeRenderer;
import com.quarkslab.quokka.util.GhidraTypeMapper;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import quokka.QuokkaOuterClass.Quokka;

import java.util.*;

/**
 * Phase 3: Export Type[] with the pinned invariant:
 *   indices 0-8 = primitives (BaseType enum order)
 *   9..K        = all other types (enums, struct/union, pointers, arrays, typedefs)
 *
 * All types are registered (index assigned) before any cross-references
 * are resolved, so forward references (e.g. pointer-to-typedef) work
 * regardless of ordering.
 */
public class TypeExporter {

    /** Classification of a Ghidra DataType for export purposes. */
    public enum TypeKind {
        ENUM, STRUCT, UNION, POINTER, ARRAY, TYPEDEF,
        FUNC_DEF, PRIMITIVE, UNKNOWN
    }

    private TypeExporter() {}

    /** Classify a Ghidra DataType into a TypeKind. */
    public static TypeKind classify(DataType dt) {
        if (dt instanceof ghidra.program.model.data.Enum)   return TypeKind.ENUM;
        if (dt instanceof TypeDef)                           return TypeKind.TYPEDEF;
        if (dt instanceof Structure)                         return TypeKind.STRUCT;
        if (dt instanceof Union)                             return TypeKind.UNION;
        if (dt instanceof Pointer)                           return TypeKind.POINTER;
        if (dt instanceof Array)                             return TypeKind.ARRAY;
        if (dt instanceof FunctionDefinition)                return TypeKind.FUNC_DEF;
        if (GhidraTypeMapper.mapPrimitive(dt) != null)       return TypeKind.PRIMITIVE;
        return TypeKind.UNKNOWN;
    }

    /**
     * Compute the registration key for a non-primitive, non-enum type.
     * Must match the keys used in ExportContext.resolveTypeIndex().
     */
    public static String typeKey(DataType dt, TypeKind kind) {
        switch (kind) {
            case STRUCT:  return dt.getName() + ":STRUCT";
            case UNION:   return dt.getName() + ":UNION";
            case POINTER: return dt.getName() + ":POINTER";
            case ARRAY:   return dt.getName() + ":ARRAY";
            case TYPEDEF: return dt.getName() + ":TYPEDEF";
            default:
                throw new IllegalArgumentException(
                        "No type key for kind: " + kind);
        }
    }

    public static void export(ExportContext ctx, Quokka.Builder builder) {
        Program program = ctx.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // Step 1: Write 9 primitive types (indices 0-8, always)
        for (int i = 0; i <= 8; i++) {
            Quokka.BaseType bt = Quokka.BaseType.forNumber(i);
            builder.addTypes(Quokka.Type.newBuilder().setPrimitiveType(bt));
        }

        // Step 2: Classify, collect, and register all types from DataTypeManager.
        // Registration happens immediately so resolveTypeIndex works for
        // any cross-reference regardless of ordering.
        List<ClassifiedType> collected = new ArrayList<>();
        int skippedFuncDefs = 0;
        int skippedDuplicates = 0;
        List<String> unhandledTypes = new ArrayList<>();

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            TypeKind kind = classify(dt);

            switch (kind) {
                case ENUM:
                    if (ctx.hasEnumType(dt.getName())) {
                        skippedDuplicates++;
                        break;
                    }
                    ctx.registerEnumType(dt.getName());
                    collected.add(new ClassifiedType(dt, kind));
                    break;
                case STRUCT: case UNION: case POINTER: case ARRAY: case TYPEDEF: {
                    String key = typeKey(dt, kind);
                    if (ctx.hasCompositeType(key)) {
                        skippedDuplicates++;
                        break;
                    }
                    ctx.registerCompositeType(key);
                    collected.add(new ClassifiedType(dt, kind));
                    break;
                }
                case FUNC_DEF:
                    skippedFuncDefs++;
                    break;
                case PRIMITIVE:
                    // Handled via indices 0-8; no explicit collection needed
                    break;
                default:
                    unhandledTypes.add(
                            dt.getName() + " (" + dt.getClass().getSimpleName() + ")");
                    break;
            }
        }

        if (skippedDuplicates > 0) {
            Msg.info(TypeExporter.class,
                    "Skipped " + skippedDuplicates + " duplicate type definitions");
        }
        if (skippedFuncDefs > 0) {
            Msg.info(TypeExporter.class,
                    "Skipped " + skippedFuncDefs + " FunctionDefinition types "
                    + "(not representable in proto)");
        }
        if (!unhandledTypes.isEmpty()) {
            Msg.warn(TypeExporter.class,
                    "Skipped " + unhandledTypes.size()
                    + " unrepresentable types: " + unhandledTypes);
        }

        // Step 3: Export all collected types (all indices already registered)
        for (ClassifiedType ct : collected) {
            builder.addTypes(buildType(ctx, ct.dt, ct.kind));
        }
    }

    // ------------------------------------------------------------------
    // Type building
    // ------------------------------------------------------------------

    private static Quokka.Type.Builder buildType(
            ExportContext ctx, DataType dt, TypeKind kind) {
        Quokka.Type.Builder tb = Quokka.Type.newBuilder();
        switch (kind) {
            case ENUM:
                tb.setEnumType(buildEnum(
                        (ghidra.program.model.data.Enum) dt));
                break;
            case STRUCT: case UNION: {
                Quokka.CompositeType.Builder cb = buildStructOrUnion(dt, kind);
                fillMembers(ctx, dt, cb);
                tb.setCompositeType(cb);
                break;
            }
            case POINTER:
                tb.setCompositeType(buildReferenceComposite(ctx, dt,
                        Quokka.CompositeType.CompositeSubType.TYPE_POINTER,
                        ((Pointer) dt).getDataType()));
                break;
            case ARRAY:
                tb.setCompositeType(buildReferenceComposite(ctx, dt,
                        Quokka.CompositeType.CompositeSubType.TYPE_ARRAY,
                        ((Array) dt).getDataType()));
                break;
            case TYPEDEF:
                tb.setCompositeType(buildReferenceComposite(ctx, dt,
                        Quokka.CompositeType.CompositeSubType.TYPE_TYPEDEF,
                        ((TypeDef) dt).getDataType()));
                break;
            default:
                break;
        }
        return tb;
    }

    private static Quokka.EnumType.Builder buildEnum(
            ghidra.program.model.data.Enum enumDt) {
        Quokka.EnumType.Builder eb = Quokka.EnumType.newBuilder()
                .setName(enumDt.getName());

        for (String valueName : enumDt.getNames()) {
            eb.addValues(Quokka.EnumType.EnumValue.newBuilder()
                    .setName(valueName)
                    .setValue(enumDt.getValue(valueName)));
        }

        Quokka.BaseType baseType = GhidraTypeMapper.mapBySize(enumDt.getLength());
        eb.setBaseType(GhidraTypeMapper.baseTypeIndex(baseType));

        setCStr(eb, enumDt);
        return eb;
    }

    /** Build a CompositeType for struct or union (without members). */
    private static Quokka.CompositeType.Builder buildStructOrUnion(
            DataType dt, TypeKind kind) {
        Quokka.CompositeType.Builder cb = Quokka.CompositeType.newBuilder()
                .setName(dt.getName())
                .setType(kind == TypeKind.UNION
                        ? Quokka.CompositeType.CompositeSubType.TYPE_UNION
                        : Quokka.CompositeType.CompositeSubType.TYPE_STRUCT)
                .setSize(dt.getLength());
        setCStr(cb, dt);
        return cb;
    }

    /**
     * Build a CompositeType for pointer, array, or typedef -- types that
     * reference a single inner type via elementTypeIdx.
     */
    private static Quokka.CompositeType.Builder buildReferenceComposite(
            ExportContext ctx, DataType dt,
            Quokka.CompositeType.CompositeSubType subType,
            DataType innerType) {
        Quokka.CompositeType.Builder cb = Quokka.CompositeType.newBuilder()
                .setName(dt.getName())
                .setType(subType)
                .setSize(dt.getLength());
        if (innerType != null) {
            cb.setElementTypeIdx(ctx.resolveTypeIndex(innerType));
        }
        setCStr(cb, dt);
        return cb;
    }

    // ------------------------------------------------------------------
    // Members
    // ------------------------------------------------------------------

    private static void fillMembers(ExportContext ctx, DataType dt,
            Quokka.CompositeType.Builder cb) {
        boolean isUnion = dt instanceof Union;
        DataTypeComponent[] components = isUnion
                ? ((Union) dt).getComponents()
                : ((Structure) dt).getDefinedComponents();

        for (DataTypeComponent comp : components) {
            Quokka.CompositeType.Member.Builder member =
                    Quokka.CompositeType.Member.newBuilder();

            member.setOffset(isUnion ? 0 : comp.getOffset() * 8);

            String memberName = comp.getFieldName();
            if (memberName == null || memberName.isEmpty()) {
                memberName = comp.getDefaultFieldName();
            }
            member.setName(memberName != null ? memberName : "");

            member.setTypeIndex(ctx.resolveTypeIndex(comp.getDataType()));
            member.setSize(comp.getLength() * 8);

            cb.addMembers(member);
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static void setCStr(Quokka.CompositeType.Builder cb, DataType dt) {
        String cStr = CTypeRenderer.render(dt);
        if (cStr != null && !cStr.isEmpty()) {
            cb.setCStr(cStr);
        }
    }

    private static void setCStr(Quokka.EnumType.Builder eb,
            ghidra.program.model.data.Enum dt) {
        String cStr = CTypeRenderer.render(dt);
        if (cStr != null && !cStr.isEmpty()) {
            eb.setCStr(cStr);
        }
    }

    // ------------------------------------------------------------------
    // Type-to-type cross-references
    // ------------------------------------------------------------------

    /** Sentinel for member_index meaning "the whole type". */
    private static final int WHOLE_TYPE = -1;

    /**
     * Emit type-to-type cross-references for all exported types.
     *
     * Ghidra has no explicit type-to-type xref API, but member/element type
     * information is native to Ghidra's DataType hierarchy
     * (DataTypeComponent.getDataType(), Pointer.getDataType(), etc.).
     * This method walks the already-built proto types and emits Reference
     * messages with DataTypeIdentifier source and destination for:
     *   - struct/union members whose type is another exported type
     *   - pointer/array/typedef types whose inner type is another exported type
     *
     * Must be called after export() so all type indices are registered and
     * the types[] array in the builder is populated.
     *
     * @return the number of type-to-type references emitted
     */
    public static int exportTypeToTypeRefs(ExportContext ctx,
            Quokka.Builder builder) {
        int emitted = 0;

        for (int typeIdx = 9; typeIdx < builder.getTypesCount(); typeIdx++) {
            Quokka.Type.Builder tb = builder.getTypesBuilder(typeIdx);

            if (tb.hasCompositeType()) {
                Quokka.CompositeType.Builder ct = tb.getCompositeTypeBuilder();

                switch (ct.getType()) {
                    case TYPE_STRUCT:
                    case TYPE_UNION:
                        for (int mIdx = 0; mIdx < ct.getMembersCount(); mIdx++) {
                            int memberTypeIdx = ct.getMembers(mIdx).getTypeIndex();
                            if (memberTypeIdx >= 9) {
                                int refIdx = emitTypeRef(builder,
                                        typeIdx, mIdx, memberTypeIdx);
                                ct.addXrefFrom(refIdx);
                                ct.getMembersBuilder(mIdx).addXrefFrom(refIdx);
                                addXrefTo(builder, memberTypeIdx, refIdx);
                                emitted++;
                            }
                        }
                        break;

                    case TYPE_POINTER:
                    case TYPE_ARRAY:
                    case TYPE_TYPEDEF:
                        if (ct.hasElementTypeIdx()
                                && ct.getElementTypeIdx() >= 9) {
                            int refIdx = emitTypeRef(builder,
                                    typeIdx, WHOLE_TYPE,
                                    ct.getElementTypeIdx());
                            ct.addXrefFrom(refIdx);
                            addXrefTo(builder, ct.getElementTypeIdx(), refIdx);
                            emitted++;
                        }
                        break;

                    default:
                        break;
                }
            }
            // EnumType members do not reference other types; skip.
        }

        return emitted;
    }

    /**
     * Add a type-to-type Reference to the global references[] array.
     * Source is {srcTypeIdx, srcMemberIdx}, destination is {dstTypeIdx, WHOLE_TYPE}.
     *
     * @return the index of the newly added reference in builder.references
     */
    private static int emitTypeRef(Quokka.Builder builder,
            int srcTypeIdx, int srcMemberIdx, int dstTypeIdx) {
        int refIdx = builder.getReferencesCount();
        builder.addReferences(Quokka.Reference.newBuilder()
                .setSource(Quokka.Reference.Location.newBuilder()
                        .setDataTypeIdentifier(
                                Quokka.DataTypeIdentifier.newBuilder()
                                        .setTypeIndex(srcTypeIdx)
                                        .setMemberIndex(srcMemberIdx)))
                .setDestination(Quokka.Reference.Location.newBuilder()
                        .setDataTypeIdentifier(
                                Quokka.DataTypeIdentifier.newBuilder()
                                        .setTypeIndex(dstTypeIdx)
                                        .setMemberIndex(WHOLE_TYPE)))
                .setReferenceType(Quokka.EdgeType.EDGE_DATA_READ));
        return refIdx;
    }

    /**
     * Add a reference index to the xref_to list of the destination type.
     */
    private static void addXrefTo(Quokka.Builder builder,
            int typeIdx, long refIdx) {
        Quokka.Type.Builder destType = builder.getTypesBuilder(typeIdx);
        if (destType.hasCompositeType()) {
            destType.getCompositeTypeBuilder().addXrefTo(refIdx);
        } else if (destType.hasEnumType()) {
            destType.getEnumTypeBuilder().addXrefTo(refIdx);
        }
    }

    /** Pairs a DataType with its pre-computed TypeKind to avoid re-classification. */
    private static final class ClassifiedType {
        final DataType dt;
        final TypeKind kind;

        ClassifiedType(DataType dt, TypeKind kind) {
            this.dt = dt;
            this.kind = kind;
        }
    }
}
