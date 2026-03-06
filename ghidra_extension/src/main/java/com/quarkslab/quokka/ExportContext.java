package com.quarkslab.quokka;

import com.quarkslab.quokka.export.TypeExporter;
import com.quarkslab.quokka.util.AddressUtil;
import com.quarkslab.quokka.util.AddressUtil.SegmentInfo;
import com.quarkslab.quokka.util.GhidraTypeMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;

import java.io.File;
import java.util.*;

/**
 * Shared export state passed through all pipeline phases.
 * Holds segment map, type indices, and address resolution logic.
 */
public class ExportContext {

    private final Program program;
    private final File outputFile;
    private final Quokka.ExporterMeta.Mode mode;
    private final TaskMonitor monitor;

    // Populated by SegmentExporter
    private List<SegmentInfo> segments;

    // Populated by TypeExporter
    private int nextTypeIndex = 9; // after primitives 0-8
    private final Map<String, Integer> enumTypeIndices = new LinkedHashMap<>();
    private final Map<String, Integer> compositeTypeIndices = new LinkedHashMap<>();

    public ExportContext(Program program, File outputFile,
            Quokka.ExporterMeta.Mode mode, TaskMonitor monitor) {
        this.program = program;
        this.outputFile = outputFile;
        this.mode = mode;
        this.monitor = monitor;
    }

    public Program getProgram() { return program; }
    public File getOutputFile() { return outputFile; }
    public Quokka.ExporterMeta.Mode getMode() { return mode; }
    public TaskMonitor getMonitor() { return monitor; }

    // --- Segment resolution ---

    public void setSegments(List<SegmentInfo> segments) {
        this.segments = segments;
    }

    public List<SegmentInfo> getSegments() {
        return segments;
    }

    /**
     * Find the segment index for an address. Returns -1 if not found.
     */
    public int resolveSegmentIndex(Address addr) {
        return AddressUtil.findSegmentIndex(segments, addr);
    }

    /**
     * Compute the segment-relative offset for an address.
     */
    public long resolveSegmentOffset(Address addr) {
        int idx = resolveSegmentIndex(addr);
        if (idx < 0) {
            return 0;
        }
        return AddressUtil.segmentOffset(addr, segments.get(idx));
    }

    /**
     * Compute the file offset for an address.
     * Returns -1 if the address has no file backing.
     */
    public long resolveFileOffset(Address addr) {
        MemoryBlock block = program.getMemory().getBlock(addr);
        return AddressUtil.fileOffset(block, addr);
    }

    // --- Type resolution ---

    /**
     * Register an enum type and return its index.
     * If already registered, returns the existing index.
     */
    public int registerEnumType(String name) {
        Integer existing = enumTypeIndices.get(name);
        if (existing != null) return existing;
        int idx = nextTypeIndex++;
        enumTypeIndices.put(name, idx);
        return idx;
    }

    /**
     * Register a composite type and return its index.
     * If already registered, returns the existing index.
     */
    public int registerCompositeType(String key) {
        Integer existing = compositeTypeIndices.get(key);
        if (existing != null) return existing;
        int idx = nextTypeIndex++;
        compositeTypeIndices.put(key, idx);
        return idx;
    }

    /** Check if an enum type is already registered. */
    public boolean hasEnumType(String name) {
        return enumTypeIndices.containsKey(name);
    }

    /** Check if a composite type is already registered. */
    public boolean hasCompositeType(String key) {
        return compositeTypeIndices.containsKey(key);
    }

    public int getNextTypeIndex() { return nextTypeIndex; }

    /**
     * Resolve a Ghidra DataType to a proto type index.
     * Returns 0 (TYPE_UNK) for unrepresentable types.
     */
    public int resolveTypeIndex(DataType dt) {
        if (dt == null) {
            return 0; // TYPE_UNK
        }

        // Check primitive types first
        Quokka.BaseType baseType = GhidraTypeMapper.mapPrimitive(dt);
        if (baseType != null) {
            return GhidraTypeMapper.baseTypeIndex(baseType);
        }

        TypeExporter.TypeKind kind = TypeExporter.classify(dt);

        if (kind == TypeExporter.TypeKind.ENUM) {
            Integer idx = enumTypeIndices.get(dt.getName());
            if (idx != null) return idx;
        } else if (kind != TypeExporter.TypeKind.FUNC_DEF
                && kind != TypeExporter.TypeKind.PRIMITIVE
                && kind != TypeExporter.TypeKind.UNKNOWN) {
            Integer idx = compositeTypeIndices.get(
                    TypeExporter.typeKey(dt, kind));
            if (idx != null) return idx;
        }

        Msg.warn(ExportContext.class,
                "Cannot resolve type index for: " + dt.getName()
                + " (" + dt.getClass().getSimpleName() + "), using TYPE_UNK");
        return 0; // TYPE_UNK
    }
}
