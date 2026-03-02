package com.quarkslab.quokka.util;

import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.assertEquals;

public class IsaMapperTest {

    @Test
    public void testX86() {
        assertEquals(Quokka.Meta.ISA.PROC_INTEL, IsaMapper.map("x86"));
    }

    @Test
    public void testARM() {
        assertEquals(Quokka.Meta.ISA.PROC_ARM, IsaMapper.map("ARM"));
    }

    @Test
    public void testAARCH64() {
        assertEquals(Quokka.Meta.ISA.PROC_ARM, IsaMapper.map("AARCH64"));
    }

    @Test
    public void testMIPS() {
        assertEquals(Quokka.Meta.ISA.PROC_MIPS, IsaMapper.map("MIPS"));
    }

    @Test
    public void testPowerPC() {
        assertEquals(Quokka.Meta.ISA.PROC_PPC, IsaMapper.map("PowerPC"));
    }

    @Test
    public void testDalvik() {
        assertEquals(Quokka.Meta.ISA.PROC_DALVIK, IsaMapper.map("Dalvik"));
    }

    @Test
    public void testUnknownProcessor() {
        assertEquals(Quokka.Meta.ISA.PROC_UNK, IsaMapper.map("SPARC"));
    }

    @Test
    public void testNull() {
        assertEquals(Quokka.Meta.ISA.PROC_UNK, IsaMapper.map(null));
    }
}
