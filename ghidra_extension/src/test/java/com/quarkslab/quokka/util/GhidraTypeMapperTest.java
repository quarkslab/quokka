package com.quarkslab.quokka.util;

import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.assertEquals;

public class GhidraTypeMapperTest {

    @Test
    public void testMapBySizeByte() {
        assertEquals(Quokka.BaseType.TYPE_B, GhidraTypeMapper.mapBySize(1));
    }

    @Test
    public void testMapBySizeWord() {
        assertEquals(Quokka.BaseType.TYPE_W, GhidraTypeMapper.mapBySize(2));
    }

    @Test
    public void testMapBySizeDword() {
        assertEquals(Quokka.BaseType.TYPE_DW, GhidraTypeMapper.mapBySize(4));
    }

    @Test
    public void testMapBySizeQword() {
        assertEquals(Quokka.BaseType.TYPE_QW, GhidraTypeMapper.mapBySize(8));
    }

    @Test
    public void testMapBySizeOword() {
        assertEquals(Quokka.BaseType.TYPE_OW, GhidraTypeMapper.mapBySize(16));
    }

    @Test
    public void testMapBySizeUnknown() {
        assertEquals(Quokka.BaseType.TYPE_UNK, GhidraTypeMapper.mapBySize(3));
        assertEquals(Quokka.BaseType.TYPE_UNK, GhidraTypeMapper.mapBySize(0));
        assertEquals(Quokka.BaseType.TYPE_UNK, GhidraTypeMapper.mapBySize(32));
    }

    @Test
    public void testBaseTypeIndexOrder() {
        // Verify the pinned index invariant: indices 0-8 match BaseType enum order
        assertEquals(0, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_UNK));
        assertEquals(1, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_B));
        assertEquals(2, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_W));
        assertEquals(3, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_DW));
        assertEquals(4, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_QW));
        assertEquals(5, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_OW));
        assertEquals(6, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_FLOAT));
        assertEquals(7, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_DOUBLE));
        assertEquals(8, GhidraTypeMapper.baseTypeIndex(Quokka.BaseType.TYPE_VOID));
    }
}
