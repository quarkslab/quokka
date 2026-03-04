package com.quarkslab.quokka.util;

import ghidra.program.model.listing.Function;
import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FunctionTypeMapperTest {

    @Test
    public void testNormalFunction() {
        Function func = mock(Function.class);
        when(func.isThunk()).thenReturn(false);
        when(func.isExternal()).thenReturn(false);

        assertEquals(Quokka.Function.FunctionType.TYPE_NORMAL,
                FunctionTypeMapper.map(func));
    }

    @Test
    public void testThunkFunction() {
        Function func = mock(Function.class);
        when(func.isThunk()).thenReturn(true);
        when(func.isExternal()).thenReturn(false);

        assertEquals(Quokka.Function.FunctionType.TYPE_THUNK,
                FunctionTypeMapper.map(func));
    }

    @Test
    public void testExternalFunction() {
        Function func = mock(Function.class);
        when(func.isThunk()).thenReturn(false);
        when(func.isExternal()).thenReturn(true);

        assertEquals(Quokka.Function.FunctionType.TYPE_IMPORTED,
                FunctionTypeMapper.map(func));
    }

    @Test
    public void testThunkPrecedesExternal() {
        // If both isThunk and isExternal are true, thunk takes precedence
        Function func = mock(Function.class);
        when(func.isThunk()).thenReturn(true);
        when(func.isExternal()).thenReturn(true);

        assertEquals(Quokka.Function.FunctionType.TYPE_THUNK,
                FunctionTypeMapper.map(func));
    }
}
