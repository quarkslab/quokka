package com.quarkslab.quokka;

import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.*;

/**
 * Unit tests for the ExportPipeline protobuf output structure.
 * These tests verify proto message construction without a running Ghidra instance.
 * Full integration tests (with ProgramBuilder) require the Ghidra test framework.
 */
public class ExportPipelineTest {

    @Test
    public void testPrimitiveTypeIndices() {
        // Verify the pinned type index invariant
        Quokka.Builder builder = Quokka.newBuilder();

        // Add 9 primitive types exactly as TypeExporter does
        for (int i = 0; i <= 8; i++) {
            Quokka.BaseType bt = Quokka.BaseType.forNumber(i);
            assertNotNull("BaseType should exist for index " + i, bt);
            builder.addTypes(Quokka.Type.newBuilder().setPrimitiveType(bt));
        }

        assertEquals(9, builder.getTypesCount());

        // Verify each primitive is at the correct index
        for (int i = 0; i <= 8; i++) {
            Quokka.Type type = builder.getTypes(i);
            assertTrue("Type at index " + i + " should be primitive",
                    type.hasPrimitiveType());
            assertEquals("Type at index " + i + " should have correct BaseType",
                    i, type.getPrimitiveType().getNumber());
        }
    }

    @Test
    public void testExporterMetaConstruction() {
        Quokka.ExporterMeta meta = Quokka.ExporterMeta.newBuilder()
                .setMode(Quokka.ExporterMeta.Mode.MODE_LIGHT)
                .setVersion("1.0.0")
                .build();

        assertEquals(Quokka.ExporterMeta.Mode.MODE_LIGHT, meta.getMode());
        assertEquals("1.0.0", meta.getVersion());
    }

    @Test
    public void testMetaConstruction() {
        Quokka.Meta meta = Quokka.Meta.newBuilder()
                .setExecutableName("test.bin")
                .setIsa(Quokka.Meta.ISA.PROC_INTEL)
                .setEndianess(Quokka.Meta.Endianess.END_LE)
                .setAddressSize(Quokka.AddressSize.ADDR_64)
                .setHash(Quokka.Meta.Hash.newBuilder()
                        .setHashType(Quokka.Meta.Hash.HashType.HASH_SHA256)
                        .setHashValue("abc123"))
                .setBackend(Quokka.Meta.Backend.newBuilder()
                        .setName(Quokka.Meta.Backend.Disassembler.DISASS_GHIDRA)
                        .setVersion("12.0.3"))
                .build();

        assertEquals("test.bin", meta.getExecutableName());
        assertEquals(Quokka.Meta.ISA.PROC_INTEL, meta.getIsa());
        assertEquals(Quokka.Meta.Endianess.END_LE, meta.getEndianess());
        assertEquals(Quokka.Meta.Backend.Disassembler.DISASS_GHIDRA,
                meta.getBackend().getName());
    }

    @Test
    public void testSegmentConstruction() {
        Quokka.Segment seg = Quokka.Segment.newBuilder()
                .setName(".text")
                .setVirtualAddr(0x400000)
                .setSize(0x1000)
                .setPermissions(5) // R|X
                .setType(Quokka.Segment.Type.SEGMENT_CODE)
                .setAddressSize(Quokka.AddressSize.ADDR_64)
                .setFileOffset(0x1000)
                .build();

        assertEquals(".text", seg.getName());
        assertEquals(0x400000, seg.getVirtualAddr());
        assertEquals(0x1000, seg.getSize());
        assertEquals(5, seg.getPermissions());
        assertEquals(Quokka.Segment.Type.SEGMENT_CODE, seg.getType());
    }

    @Test
    public void testFunctionWithBlocksConstruction() {
        Quokka.Function func = Quokka.Function.newBuilder()
                .setSegmentIndex(0)
                .setSegmentOffset(0x100)
                .setFileOffset(0x1100)
                .setFunctionType(Quokka.Function.FunctionType.TYPE_NORMAL)
                .setName("main")
                .addBlocks(Quokka.Block.newBuilder()
                        .setSegmentIndex(0)
                        .setSegmentOffset(0x100)
                        .setFileOffset(0x1100)
                        .setBlockType(Quokka.Block.BlockType.BLOCK_TYPE_NORMAL)
                        .setSize(32)
                        .setNInstr(5))
                .addBlocks(Quokka.Block.newBuilder()
                        .setSegmentIndex(0)
                        .setSegmentOffset(0x120)
                        .setFileOffset(0x1120)
                        .setBlockType(Quokka.Block.BlockType.BLOCK_TYPE_RET)
                        .setSize(16)
                        .setNInstr(3))
                .addEdges(Quokka.Function.Edge.newBuilder()
                        .setEdgeType(Quokka.EdgeType.EDGE_JUMP_UNCOND)
                        .setSource(0)
                        .setDestination(1))
                .build();

        assertEquals("main", func.getName());
        assertEquals(2, func.getBlocksCount());
        assertEquals(1, func.getEdgesCount());
        assertEquals(32, func.getBlocks(0).getSize());
        assertEquals(5, func.getBlocks(0).getNInstr());
        // instruction_index should be empty in LIGHT mode
        assertEquals(0, func.getBlocks(0).getInstructionIndexCount());
    }

    @Test
    public void testReferenceConstruction() {
        Quokka.Reference ref = Quokka.Reference.newBuilder()
                .setSource(Quokka.Reference.Location.newBuilder()
                        .setAddress(0x401000))
                .setDestination(Quokka.Reference.Location.newBuilder()
                        .setAddress(0x402000))
                .setReferenceType(Quokka.EdgeType.EDGE_CALL)
                .build();

        assertEquals(0x401000, ref.getSource().getAddress());
        assertEquals(0x402000, ref.getDestination().getAddress());
        assertEquals(Quokka.EdgeType.EDGE_CALL, ref.getReferenceType());
    }

    @Test
    public void testLayoutConstruction() {
        Quokka.Layout layout = Quokka.Layout.newBuilder()
                .setAddressRange(Quokka.Layout.AddressRange.newBuilder()
                        .setStartAddress(0x400000)
                        .setSize(0x100))
                .setLayoutType(Quokka.Layout.LayoutType.LAYOUT_CODE)
                .build();

        assertEquals(0x400000, layout.getAddressRange().getStartAddress());
        assertEquals(0x100, layout.getAddressRange().getSize());
        assertEquals(Quokka.Layout.LayoutType.LAYOUT_CODE,
                layout.getLayoutType());
    }

    @Test
    public void testFullProtoRoundtrip() throws Exception {
        // Build a minimal but complete Quokka proto
        Quokka proto = Quokka.newBuilder()
                .setExporterMeta(Quokka.ExporterMeta.newBuilder()
                        .setMode(Quokka.ExporterMeta.Mode.MODE_LIGHT)
                        .setVersion("1.0.0"))
                .setMeta(Quokka.Meta.newBuilder()
                        .setExecutableName("test")
                        .setIsa(Quokka.Meta.ISA.PROC_INTEL)
                        .setEndianess(Quokka.Meta.Endianess.END_LE)
                        .setAddressSize(Quokka.AddressSize.ADDR_64)
                        .setHash(Quokka.Meta.Hash.newBuilder()
                                .setHashType(Quokka.Meta.Hash.HashType.HASH_SHA256)
                                .setHashValue("deadbeef"))
                        .setBackend(Quokka.Meta.Backend.newBuilder()
                                .setName(Quokka.Meta.Backend.Disassembler.DISASS_GHIDRA)
                                .setVersion("12.0.3")))
                .addSegments(Quokka.Segment.newBuilder()
                        .setName(".text")
                        .setVirtualAddr(0x400000)
                        .setSize(0x1000)
                        .setPermissions(5)
                        .setType(Quokka.Segment.Type.SEGMENT_CODE)
                        .setAddressSize(Quokka.AddressSize.ADDR_64)
                        .setFileOffset(0))
                .build();

        // Serialize and deserialize
        byte[] bytes = proto.toByteArray();
        Quokka deserialized = Quokka.parseFrom(bytes);

        assertEquals(proto.getExporterMeta().getMode(),
                deserialized.getExporterMeta().getMode());
        assertEquals(proto.getMeta().getIsa(), deserialized.getMeta().getIsa());
        assertEquals(proto.getSegmentsCount(), deserialized.getSegmentsCount());
        assertEquals(proto.getSegments(0).getName(),
                deserialized.getSegments(0).getName());
    }
}
