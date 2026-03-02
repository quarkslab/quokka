package com.quarkslab.quokka.util;

import ghidra.program.model.symbol.RefType;
import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.assertEquals;

public class RefTypeMapperTest {

    // --- Jump types ---

    @Test
    public void testUnconditionalJump() {
        assertEquals(Quokka.EdgeType.EDGE_JUMP_UNCOND,
                RefTypeMapper.map(RefType.UNCONDITIONAL_JUMP));
    }

    @Test
    public void testJumpOverrideUnconditional() {
        assertEquals(Quokka.EdgeType.EDGE_JUMP_UNCOND,
                RefTypeMapper.map(RefType.JUMP_OVERRIDE_UNCONDITIONAL));
    }

    @Test
    public void testConditionalJump() {
        assertEquals(Quokka.EdgeType.EDGE_JUMP_COND,
                RefTypeMapper.map(RefType.CONDITIONAL_JUMP));
    }

    @Test
    public void testComputedJump() {
        assertEquals(Quokka.EdgeType.EDGE_JUMP_INDIR,
                RefTypeMapper.map(RefType.COMPUTED_JUMP));
    }

    @Test
    public void testConditionalComputedJump() {
        assertEquals(Quokka.EdgeType.EDGE_JUMP_INDIR,
                RefTypeMapper.map(RefType.CONDITIONAL_COMPUTED_JUMP));
    }

    // --- Call types ---

    @Test
    public void testUnconditionalCall() {
        assertEquals(Quokka.EdgeType.EDGE_CALL,
                RefTypeMapper.map(RefType.UNCONDITIONAL_CALL));
    }

    @Test
    public void testConditionalCall() {
        assertEquals(Quokka.EdgeType.EDGE_CALL,
                RefTypeMapper.map(RefType.CONDITIONAL_CALL));
    }

    @Test
    public void testCallTerminator() {
        assertEquals(Quokka.EdgeType.EDGE_CALL,
                RefTypeMapper.map(RefType.CALL_TERMINATOR));
    }

    @Test
    public void testConditionalCallTerminator() {
        assertEquals(Quokka.EdgeType.EDGE_CALL,
                RefTypeMapper.map(RefType.CONDITIONAL_CALL_TERMINATOR));
    }

    @Test
    public void testCallOverrideUnconditional() {
        assertEquals(Quokka.EdgeType.EDGE_CALL,
                RefTypeMapper.map(RefType.CALL_OVERRIDE_UNCONDITIONAL));
    }

    @Test
    public void testCallotherOverrideCall() {
        assertEquals(Quokka.EdgeType.EDGE_CALL,
                RefTypeMapper.map(RefType.CALLOTHER_OVERRIDE_CALL));
    }

    @Test
    public void testComputedCall() {
        assertEquals(Quokka.EdgeType.EDGE_CALL_INDIR,
                RefTypeMapper.map(RefType.COMPUTED_CALL));
    }

    @Test
    public void testConditionalComputedCall() {
        assertEquals(Quokka.EdgeType.EDGE_CALL_INDIR,
                RefTypeMapper.map(RefType.CONDITIONAL_COMPUTED_CALL));
    }

    @Test
    public void testComputedCallTerminator() {
        assertEquals(Quokka.EdgeType.EDGE_CALL_INDIR,
                RefTypeMapper.map(RefType.COMPUTED_CALL_TERMINATOR));
    }

    // --- Data reference types ---

    @Test
    public void testRead() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_READ,
                RefTypeMapper.map(RefType.READ));
    }

    @Test
    public void testReadWrite() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_READ,
                RefTypeMapper.map(RefType.READ_WRITE));
    }

    @Test
    public void testWrite() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_WRITE,
                RefTypeMapper.map(RefType.WRITE));
    }

    @Test
    public void testData() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.DATA));
    }

    @Test
    public void testDataInd() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.DATA_IND));
    }

    @Test
    public void testReadInd() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.READ_IND));
    }

    @Test
    public void testWriteInd() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.WRITE_IND));
    }

    @Test
    public void testReadWriteInd() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.READ_WRITE_IND));
    }

    @Test
    public void testParam() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.PARAM));
    }

    @Test
    public void testExternalRef() {
        assertEquals(Quokka.EdgeType.EDGE_DATA_INDIR,
                RefTypeMapper.map(RefType.EXTERNAL_REF));
    }

    // --- Edge cases ---

    @Test
    public void testNull() {
        assertEquals(Quokka.EdgeType.EDGE_UNKNOWN, RefTypeMapper.map(null));
    }

    @Test
    public void testFallThrough() {
        // FALL_THROUGH should map to UNKNOWN (callers typically skip it)
        assertEquals(Quokka.EdgeType.EDGE_UNKNOWN,
                RefTypeMapper.map(RefType.FALL_THROUGH));
    }

    @Test
    public void testIndirection() {
        assertEquals(Quokka.EdgeType.EDGE_UNKNOWN,
                RefTypeMapper.map(RefType.INDIRECTION));
    }
}
