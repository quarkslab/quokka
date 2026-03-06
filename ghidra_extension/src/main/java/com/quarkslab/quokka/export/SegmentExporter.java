package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.util.AddressUtil.SegmentInfo;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import quokka.QuokkaOuterClass.Quokka;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Phase 2: Export Segment[] from Ghidra MemoryBlocks.
 * 1:1 mapping with non-overlay MemoryBlocks, sorted by start VA.
 */
public class SegmentExporter {

    private SegmentExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder) {
        Program program = ctx.getProgram();

        // Collect non-overlay blocks, sorted by start address
        List<MemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isOverlay()) {
                blocks.add(block);
            }
        }
        blocks.sort(Comparator.comparing(b -> b.getStart()));

        List<SegmentInfo> segmentInfos = new ArrayList<>();

        for (MemoryBlock block : blocks) {
            // Permissions: R=4, W=2, X=1 (Linux style)
            int perms = 0;
            if (block.isRead()) perms |= 4;
            if (block.isWrite()) perms |= 2;
            if (block.isExecute()) perms |= 1;

            // Segment type
            int segType = mapSegmentType(block);

            // Address size from program default
            int ptrSize = program.getDefaultPointerSize();
            int addrSize;
            if (ptrSize == 8) {
                addrSize = Quokka.AddressSize.ADDR_64_VALUE;
            } else if (ptrSize == 4) {
                addrSize = Quokka.AddressSize.ADDR_32_VALUE;
            } else {
                addrSize = Quokka.AddressSize.ADDR_UNK_VALUE;
            }

            // File offset from SourceInfo
            long fileOffset = -1;
            List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
            if (!sourceInfos.isEmpty()) {
                long off = sourceInfos.get(0).getFileBytesOffset();
                if (off >= 0) {
                    fileOffset = off;
                }
            }

            SegmentInfo info = new SegmentInfo(
                    block.getName(),
                    block.getStart().getOffset(),
                    block.getSize(),
                    perms,
                    segType,
                    addrSize,
                    fileOffset,
                    block);
            segmentInfos.add(info);

            // Build proto segment
            Quokka.Segment.Builder segBuilder =
                    Quokka.Segment.newBuilder()
                    .setName(block.getName())
                    .setVirtualAddr(block.getStart().getOffset())
                    .setSize(block.getSize())
                    .setPermissions(perms)
                    .setTypeValue(segType)
                    .setAddressSizeValue(addrSize)
                    .setFileOffset(fileOffset);

            builder.addSegments(segBuilder);
        }

        ctx.setSegments(segmentInfos);
    }

    private static int mapSegmentType(MemoryBlock block) {
        if (block.isExecute()) {
            return Quokka.Segment.Type.SEGMENT_CODE_VALUE;
        }
        if (!block.isInitialized()) {
            return Quokka.Segment.Type.SEGMENT_BSS_VALUE;
        }
        String name = block.getName().toLowerCase();
        if (name.contains("extern")) {
            return Quokka.Segment.Type.SEGMENT_EXTERN_VALUE;
        }
        return Quokka.Segment.Type.SEGMENT_DATA_VALUE;
    }
}
