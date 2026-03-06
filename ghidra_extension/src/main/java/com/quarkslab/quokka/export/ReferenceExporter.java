package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.util.RefTypeMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import quokka.QuokkaOuterClass.Quokka;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Phase 5: Export Reference[] from Ghidra ReferenceManager.
 * Maps Ghidra RefType to proto EdgeType. Sorted by (source, dest, type).
 */
public class ReferenceExporter {

    private ReferenceExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder) {
        Program program = ctx.getProgram();
        ReferenceManager refMgr = program.getReferenceManager();

        List<RefRecord> records = new ArrayList<>();

        // Iterate over all reference sources
        AddressIterator srcIter = refMgr.getReferenceSourceIterator(
                program.getMemory(), true);
        while (srcIter.hasNext()) {
            if (ctx.getMonitor().isCancelled()) break;

            Address srcAddr = srcIter.next();
            Reference[] refs = refMgr.getReferencesFrom(srcAddr);
            for (Reference ref : refs) {
                // Skip fall-through references
                if (ref.getReferenceType() == RefType.FALL_THROUGH) {
                    continue;
                }
                // Skip stack references
                if (ref.isStackReference()) {
                    continue;
                }

                Quokka.EdgeType edgeType = RefTypeMapper.map(
                        ref.getReferenceType());

                records.add(new RefRecord(
                        srcAddr.getOffset(),
                        ref.getToAddress().getOffset(),
                        edgeType));
            }
        }

        // Sort by (source, destination, type) for determinism
        records.sort(Comparator.<RefRecord, Long>comparing(r -> r.source)
                .thenComparing(r -> r.destination)
                .thenComparing(r -> r.type.getNumber()));

        for (RefRecord rec : records) {
            builder.addReferences(Quokka.Reference.newBuilder()
                    .setSource(Quokka.Reference.Location.newBuilder()
                            .setAddress(rec.source))
                    .setDestination(Quokka.Reference.Location.newBuilder()
                            .setAddress(rec.destination))
                    .setReferenceType(rec.type));
        }
    }

    private record RefRecord(long source, long destination,
            Quokka.EdgeType type) {}
}
