package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.util.RefTypeMapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import quokka.QuokkaOuterClass.Quokka;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public static void attachInstructionXrefs(ExportContext ctx,
            Quokka.Builder builder) {
        Program program = ctx.getProgram();
        Listing listing = program.getListing();
        Map<Long, InstructionSlot> instructionSlots = new HashMap<>();

        for (int funcIdx = 0; funcIdx < builder.getFunctionsCount(); funcIdx++) {
            Quokka.Function.Builder funcBuilder =
                    builder.getFunctionsBuilder(funcIdx);
            for (int blockIdx = 0; blockIdx < funcBuilder.getBlocksCount();
                    blockIdx++) {
                Quokka.Block.Builder blockBuilder =
                        funcBuilder.getBlocksBuilder(blockIdx);
                long start = builder.getSegments(blockBuilder.getSegmentIndex())
                        .getVirtualAddr() + blockBuilder.getSegmentOffset();
                long end = start + blockBuilder.getSize();
                Address startAddr = program.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(start);

                InstructionIterator instrIter =
                        listing.getInstructions(startAddr, true);
                int instrIdx = 0;
                while (instrIter.hasNext() && instrIdx < blockBuilder.getNInstr()) {
                    Instruction instruction = instrIter.next();
                    long addr = instruction.getAddress().getOffset();
                    if (addr < start) {
                        continue;
                    }
                    if (addr >= end) {
                        break;
                    }
                    instructionSlots.put(addr,
                            new InstructionSlot(funcIdx, blockIdx, instrIdx));
                    instrIdx++;
                }
            }
        }

        for (int refIdx = 0; refIdx < builder.getReferencesCount(); refIdx++) {
            Quokka.Reference ref = builder.getReferences(refIdx);
            if (ref.getSource().hasAddress()) {
                InstructionSlot slot =
                        instructionSlots.get(ref.getSource().getAddress());
                if (slot != null) {
                    builder.getFunctionsBuilder(slot.functionIndex)
                            .getBlocksBuilder(slot.blockIndex)
                            .addInstructionsXrefFrom(
                                    Quokka.Block.InstructionXref.newBuilder()
                                            .setInstrBbIdx(slot.instructionIndex)
                                            .setXrefIndex(refIdx));
                }
            }
            if (ref.getDestination().hasAddress()) {
                InstructionSlot slot =
                        instructionSlots.get(ref.getDestination().getAddress());
                if (slot != null) {
                    builder.getFunctionsBuilder(slot.functionIndex)
                            .getBlocksBuilder(slot.blockIndex)
                            .addInstructionsXrefTo(
                                    Quokka.Block.InstructionXref.newBuilder()
                                            .setInstrBbIdx(slot.instructionIndex)
                                            .setXrefIndex(refIdx));
                }
            }
        }
    }

    private record RefRecord(long source, long destination,
            Quokka.EdgeType type) {}

    private record InstructionSlot(int functionIndex, int blockIndex,
            int instructionIndex) {}
}
