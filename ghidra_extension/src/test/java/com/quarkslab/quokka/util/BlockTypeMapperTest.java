package com.quarkslab.quokka.util;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;
import quokka.QuokkaOuterClass.Quokka;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

public class BlockTypeMapperTest {

    private CodeBlock mockBlock(Address minAddr, Address maxAddr) {
        CodeBlock block = mock(CodeBlock.class);
        when(block.getMinAddress()).thenReturn(minAddr);
        when(block.getMaxAddress()).thenReturn(maxAddr);
        return block;
    }

    private Program mockProgram(MemoryBlock memBlock, Instruction lastInstr,
            Address maxAddr) {
        Memory memory = mock(Memory.class);
        when(memory.getBlock(any(Address.class))).thenReturn(memBlock);

        Listing listing = mock(Listing.class);
        when(listing.getInstructionContaining(maxAddr)).thenReturn(lastInstr);

        Program program = mock(Program.class);
        when(program.getMemory()).thenReturn(memory);
        when(program.getListing()).thenReturn(listing);
        return program;
    }

    @Test
    public void testExternBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // Memory.getBlock returns null -> EXTERN
        Memory memory = mock(Memory.class);
        when(memory.getBlock(minAddr)).thenReturn(null);
        Program program = mock(Program.class);
        when(program.getMemory()).thenReturn(memory);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_EXTERN,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }

    @Test
    public void testNormalBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // Last instruction has simple fall-through flow
        Instruction instr = mock(Instruction.class);
        when(instr.getFlowType()).thenReturn(RefType.FALL_THROUGH);

        Program program = mockProgram(mock(MemoryBlock.class), instr, maxAddr);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_NORMAL,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }

    @Test
    public void testRetBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // Terminal non-call, non-conditional -> RET
        FlowType flowType = mock(FlowType.class);
        when(flowType.isTerminal()).thenReturn(true);
        when(flowType.isCall()).thenReturn(false);
        when(flowType.isConditional()).thenReturn(false);

        Instruction instr = mock(Instruction.class);
        when(instr.getFlowType()).thenReturn(flowType);

        Program program = mockProgram(mock(MemoryBlock.class), instr, maxAddr);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_RET,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }

    @Test
    public void testConditionalRetBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // Terminal + conditional + non-call -> CNDRET
        FlowType flowType = mock(FlowType.class);
        when(flowType.isTerminal()).thenReturn(true);
        when(flowType.isCall()).thenReturn(false);
        when(flowType.isConditional()).thenReturn(true);

        Instruction instr = mock(Instruction.class);
        when(instr.getFlowType()).thenReturn(flowType);

        Program program = mockProgram(mock(MemoryBlock.class), instr, maxAddr);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_CNDRET,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }

    @Test
    public void testIndirectJumpBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // Computed jump -> INDJUMP
        FlowType flowType = mock(FlowType.class);
        when(flowType.isTerminal()).thenReturn(false);
        when(flowType.isJump()).thenReturn(true);
        when(flowType.isComputed()).thenReturn(true);

        Instruction instr = mock(Instruction.class);
        when(instr.getFlowType()).thenReturn(flowType);

        Program program = mockProgram(mock(MemoryBlock.class), instr, maxAddr);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_INDJUMP,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }

    @Test
    public void testNoRetBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // Call with no fallthrough -> NORET
        FlowType flowType = mock(FlowType.class);
        when(flowType.isTerminal()).thenReturn(false);
        when(flowType.isJump()).thenReturn(false);
        when(flowType.isCall()).thenReturn(true);
        when(flowType.hasFallthrough()).thenReturn(false);

        Instruction instr = mock(Instruction.class);
        when(instr.getFlowType()).thenReturn(flowType);

        Program program = mockProgram(mock(MemoryBlock.class), instr, maxAddr);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_NORET,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }

    @Test
    public void testNoInstructionBlock() {
        Address minAddr = mock(Address.class);
        Address maxAddr = mock(Address.class);
        CodeBlock block = mockBlock(minAddr, maxAddr);

        // No instruction at maxAddress -> NORMAL fallback
        Program program = mockProgram(mock(MemoryBlock.class), null, maxAddr);

        assertEquals(Quokka.Block.BlockType.BLOCK_TYPE_NORMAL,
                BlockTypeMapper.map(block, program, TaskMonitor.DUMMY));
    }
}
