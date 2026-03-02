package com.quarkslab.quokka.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

import java.util.Collections;
import java.util.List;

/**
 * Address resolution utilities for segment-relative addressing.
 * All proto addresses are (segment_index, segment_offset, file_offset) tuples.
 */
public final class AddressUtil {

    private AddressUtil() {}

    /**
     * Find the segment index for an address via binary search.
     * Segments must be sorted by start address.
     * Returns -1 if address doesn't belong to any segment.
     */
    public static int findSegmentIndex(List<SegmentInfo> segments, Address addr) {
        long offset = addr.getOffset();

        int lo = 0;
        int hi = segments.size() - 1;
        int result = -1;

        while (lo <= hi) {
            int mid = (lo + hi) >>> 1;
            long segStart = segments.get(mid).startOffset();
            if (segStart <= offset) {
                result = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }

        if (result >= 0) {
            SegmentInfo seg = segments.get(result);
            if (offset < seg.startOffset() + seg.size()) {
                return result;
            }
        }
        return -1;
    }

    /**
     * Compute the segment-relative offset for an address.
     */
    public static long segmentOffset(Address addr, SegmentInfo segment) {
        return addr.getOffset() - segment.startOffset();
    }

    /**
     * Compute the file offset for an address within a memory block.
     * Returns -1 if the block has no file backing.
     */
    public static long fileOffset(MemoryBlock block, Address addr) {
        if (block == null || !block.isInitialized()) {
            return -1;
        }
        try {
            var sourceInfos = block.getSourceInfos();
            if (sourceInfos.isEmpty()) {
                return -1;
            }
            var sourceInfo = sourceInfos.get(0);
            long blockFileOffset = sourceInfo.getFileBytesOffset();
            if (blockFileOffset < 0) {
                return -1;
            }
            long offsetInBlock = addr.getOffset() - block.getStart().getOffset();
            return blockFileOffset + offsetInBlock;
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Immutable record holding segment metadata for address resolution.
     */
    public record SegmentInfo(
            String name,
            long startOffset,
            long size,
            int permissions,
            int protoSegType,
            int protoAddrSize,
            long fileOffset,
            MemoryBlock memoryBlock
    ) {
        /**
         * Check if an address offset falls within this segment.
         */
        public boolean contains(long addrOffset) {
            return addrOffset >= startOffset && addrOffset < startOffset + size;
        }
    }
}
