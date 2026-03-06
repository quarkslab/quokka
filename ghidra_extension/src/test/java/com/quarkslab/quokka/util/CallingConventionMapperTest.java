package com.quarkslab.quokka.util;

import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.assertEquals;

public class CallingConventionMapperTest {

    @Test
    public void testCdecl() {
        assertEquals(Quokka.CallingConvention.CC_CDECL,
                CallingConventionMapper.map("__cdecl"));
    }

    @Test
    public void testStdcall() {
        assertEquals(Quokka.CallingConvention.CC_STDCALL,
                CallingConventionMapper.map("__stdcall"));
    }

    @Test
    public void testFastcall() {
        assertEquals(Quokka.CallingConvention.CC_FASTCALL,
                CallingConventionMapper.map("__fastcall"));
    }

    @Test
    public void testThiscall() {
        assertEquals(Quokka.CallingConvention.CC_THISCALL,
                CallingConventionMapper.map("__thiscall"));
    }

    @Test
    public void testPascal() {
        assertEquals(Quokka.CallingConvention.CC_PASCAL,
                CallingConventionMapper.map("__pascal"));
    }

    @Test
    public void testEllipsis() {
        assertEquals(Quokka.CallingConvention.CC_ELLIPSIS,
                CallingConventionMapper.map("__ellipsis"));
    }

    @Test
    public void testSwift() {
        assertEquals(Quokka.CallingConvention.CC_SWIFT,
                CallingConventionMapper.map("__swiftcall"));
    }

    @Test
    public void testGolang() {
        assertEquals(Quokka.CallingConvention.CC_GOLANG,
                CallingConventionMapper.map("__golang"));
    }

    @Test
    public void testUnknown() {
        assertEquals(Quokka.CallingConvention.CC_UNK,
                CallingConventionMapper.map("unknown"));
    }

    @Test
    public void testNull() {
        assertEquals(Quokka.CallingConvention.CC_UNK,
                CallingConventionMapper.map(null));
    }

    @Test
    public void testEmpty() {
        assertEquals(Quokka.CallingConvention.CC_UNK,
                CallingConventionMapper.map(""));
    }
}
