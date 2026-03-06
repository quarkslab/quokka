package com.quarkslab.quokka.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class AddressUtilTest {

    private static final GenericAddressSpace SPACE =
            new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

    private Address addr(long offset) {
        return SPACE.getAddress(offset);
    }

    // --- findSegmentIndex ---

    @Test
    public void testFindSegmentIndex_singleSegment() {
        List<AddressUtil.SegmentInfo> segments = List.of(
                new AddressUtil.SegmentInfo(".text", 0x400000, 0x1000,
                        5, 1, 2, 0, null));
        assertEquals(0, AddressUtil.findSegmentIndex(segments, addr(0x400000)));
        assertEquals(0, AddressUtil.findSegmentIndex(segments, addr(0x400FFF)));
    }

    @Test
    public void testFindSegmentIndex_pastEnd() {
        List<AddressUtil.SegmentInfo> segments = List.of(
                new AddressUtil.SegmentInfo(".text", 0x400000, 0x1000,
                        5, 1, 2, 0, null));
        assertEquals(-1, AddressUtil.findSegmentIndex(segments, addr(0x401000)));
    }

    @Test
    public void testFindSegmentIndex_beforeStart() {
        List<AddressUtil.SegmentInfo> segments = List.of(
                new AddressUtil.SegmentInfo(".text", 0x400000, 0x1000,
                        5, 1, 2, 0, null));
        assertEquals(-1, AddressUtil.findSegmentIndex(segments, addr(0x3FFFFF)));
    }

    @Test
    public void testFindSegmentIndex_multipleSegments() {
        List<AddressUtil.SegmentInfo> segments = List.of(
                new AddressUtil.SegmentInfo(".text", 0x400000, 0x1000,
                        5, 1, 2, 0, null),
                new AddressUtil.SegmentInfo(".data", 0x600000, 0x500,
                        6, 2, 2, 0x2000, null));
        assertEquals(0, AddressUtil.findSegmentIndex(segments, addr(0x400500)));
        assertEquals(1, AddressUtil.findSegmentIndex(segments, addr(0x600000)));
        assertEquals(1, AddressUtil.findSegmentIndex(segments, addr(0x6004FF)));
    }

    @Test
    public void testFindSegmentIndex_gap() {
        List<AddressUtil.SegmentInfo> segments = List.of(
                new AddressUtil.SegmentInfo(".text", 0x400000, 0x1000,
                        5, 1, 2, 0, null),
                new AddressUtil.SegmentInfo(".data", 0x600000, 0x500,
                        6, 2, 2, 0x2000, null));
        // Address in gap between segments
        assertEquals(-1, AddressUtil.findSegmentIndex(segments, addr(0x500000)));
    }

    @Test
    public void testFindSegmentIndex_emptyList() {
        assertEquals(-1, AddressUtil.findSegmentIndex(
                Collections.emptyList(), addr(0x400000)));
    }

    // --- segmentOffset ---

    @Test
    public void testSegmentOffset_start() {
        AddressUtil.SegmentInfo seg = new AddressUtil.SegmentInfo(
                ".text", 0x400000, 0x1000, 5, 1, 2, 0, null);
        assertEquals(0, AddressUtil.segmentOffset(addr(0x400000), seg));
    }

    @Test
    public void testSegmentOffset_middle() {
        AddressUtil.SegmentInfo seg = new AddressUtil.SegmentInfo(
                ".text", 0x400000, 0x1000, 5, 1, 2, 0, null);
        assertEquals(0x100, AddressUtil.segmentOffset(addr(0x400100), seg));
    }

    // --- fileOffset ---

    @Test
    public void testFileOffset_nullBlock() {
        assertEquals(-1, AddressUtil.fileOffset(null, addr(0x400000)));
    }

    // --- SegmentInfo.contains ---

    @Test
    public void testSegmentInfoContains() {
        AddressUtil.SegmentInfo seg = new AddressUtil.SegmentInfo(
                ".text", 0x400000, 0x1000, 5, 1, 2, 0, null);
        assertTrue(seg.contains(0x400000));
        assertTrue(seg.contains(0x400FFF));
        assertFalse(seg.contains(0x401000));
        assertFalse(seg.contains(0x3FFFFF));
    }
}
