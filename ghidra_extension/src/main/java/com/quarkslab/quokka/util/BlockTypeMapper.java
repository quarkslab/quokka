package com.quarkslab.quokka.util;

import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;

/**
 * Maps a CodeBlock's characteristics to proto Block.BlockType.
 * Determines block type by examining the last instruction's flow type.
 */
public final class BlockTypeMapper {

    private BlockTypeMapper() {}

    /**
     * Determine the block type from the block's last instruction flow characteristics.
     */
    public static Quokka.Block.BlockType map(CodeBlock block, Program program,
            TaskMonitor monitor) {
        // Check if block is in EXTERNAL address space
        if (program.getMemory().getBlock(block.getMinAddress()) == null) {
            return Quokka.Block.BlockType.BLOCK_TYPE_EXTERN;
        }

        // Get the last instruction in the block
        Instruction lastInstr = program.getListing().getInstructionContaining(
                block.getMaxAddress());
        if (lastInstr == null) {
            return Quokka.Block.BlockType.BLOCK_TYPE_NORMAL;
        }

        FlowType flowType = lastInstr.getFlowType();

        // Check for return/terminal types
        if (flowType.isTerminal() && !flowType.isCall()) {
            if (flowType.isConditional()) {
                return Quokka.Block.BlockType.BLOCK_TYPE_CNDRET;
            }
            return Quokka.Block.BlockType.BLOCK_TYPE_RET;
        }

        // Check for computed/indirect jumps
        if (flowType.isJump() && flowType.isComputed()) {
            return Quokka.Block.BlockType.BLOCK_TYPE_INDJUMP;
        }

        // Check for no-return calls
        if (flowType.isCall() && !flowType.hasFallthrough()) {
            return Quokka.Block.BlockType.BLOCK_TYPE_NORET;
        }

        return Quokka.Block.BlockType.BLOCK_TYPE_NORMAL;
    }
}
