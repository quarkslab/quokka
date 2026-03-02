package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import quokka.QuokkaOuterClass.Quokka;

/**
 * Phase 6: Export Layout[] -- linear scan of R|X blocks classifying
 * CODE/DATA/GAP regions. Uninitialized blocks become DATA regions
 * without byte-walking.
 */
public class LayoutExporter {

    private LayoutExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder) {
        Program program = ctx.getProgram();
        Listing listing = program.getListing();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (block.isOverlay()) continue;
            // Only process R|X blocks for layout
            if (!block.isExecute() && !block.isRead()) continue;

            if (!block.isInitialized()) {
                // Uninitialized blocks -> single DATA region (no byte-walking)
                addLayout(builder,
                        block.getStart().getOffset(),
                        block.getSize(),
                        Quokka.Layout.LayoutType.LAYOUT_DATA);
                continue;
            }

            // Walk the initialized block, classifying regions
            walkBlock(program, listing, block, builder);
        }
    }

    private static void walkBlock(Program program, Listing listing,
            MemoryBlock block, Quokka.Builder builder) {

        Address blockStart = block.getStart();
        Address blockEnd = block.getEnd();

        // Track current region
        long regionStart = blockStart.getOffset();
        Quokka.Layout.LayoutType regionType = Quokka.Layout.LayoutType.LAYOUT_GAP;
        long lastEnd = blockStart.getOffset();

        CodeUnitIterator cuIter = listing.getCodeUnits(
                program.getAddressFactory().getAddressSet(blockStart, blockEnd),
                true);

        while (cuIter.hasNext()) {
            CodeUnit cu = cuIter.next();
            Address cuAddr = cu.getMinAddress();
            long cuStart = cuAddr.getOffset();
            long cuEnd = cuStart + cu.getLength();

            Quokka.Layout.LayoutType cuType;
            if (cu instanceof Instruction) {
                cuType = Quokka.Layout.LayoutType.LAYOUT_CODE;
            } else if (cu instanceof Data && ((Data) cu).isDefined()) {
                cuType = Quokka.Layout.LayoutType.LAYOUT_DATA;
            } else {
                cuType = Quokka.Layout.LayoutType.LAYOUT_GAP;
            }

            // If type changed, flush the previous region
            if (cuType != regionType && lastEnd > regionStart) {
                addLayout(builder, regionStart, lastEnd - regionStart, regionType);
                regionStart = cuStart;
            } else if (cuStart > lastEnd && lastEnd > regionStart) {
                // Gap between code units
                addLayout(builder, regionStart, lastEnd - regionStart, regionType);
                // Insert gap region
                addLayout(builder, lastEnd, cuStart - lastEnd,
                        Quokka.Layout.LayoutType.LAYOUT_GAP);
                regionStart = cuStart;
            }

            if (lastEnd == regionStart) {
                regionType = cuType;
                regionStart = cuStart;
            }

            lastEnd = cuEnd;
        }

        // Flush final region
        if (lastEnd > regionStart) {
            addLayout(builder, regionStart, lastEnd - regionStart, regionType);
        }

        // Trailing gap at end of block
        long blockEndOffset = blockEnd.getOffset() + 1;
        if (lastEnd < blockEndOffset) {
            addLayout(builder, lastEnd, blockEndOffset - lastEnd,
                    Quokka.Layout.LayoutType.LAYOUT_GAP);
        }
    }

    private static void addLayout(Quokka.Builder builder, long startAddr,
            long size, Quokka.Layout.LayoutType type) {
        if (size <= 0) return;
        builder.addLayout(Quokka.Layout.newBuilder()
                .setAddressRange(Quokka.Layout.AddressRange.newBuilder()
                        .setStartAddress(startAddr)
                        .setSize(size))
                .setLayoutType(type));
    }
}
