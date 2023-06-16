package com.quarkslab.quokka.parsers;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka.FunctionChunk.Block.BlockType;
import quokka.QuokkaOuterClass.Quokka.Edge.EdgeType;
import com.quarkslab.quokka.models.Function;
import com.quarkslab.quokka.models.Block;
import com.quarkslab.quokka.models.Edge;
import com.quarkslab.quokka.LogManager;
import com.quarkslab.quokka.utils.Utils;

/**
 * Retrieves from ghidra the reverse engineering analysis info. This includes the disassembly
 * (functions, blocks, instructions, ...), the call graph, the CFG, etc...
 * 
 * This is basically the skeleton of the binary.
 */
public class AnalysisParser extends GhidraParser {
    private List<Function> functions = new ArrayList<>();
    private Set<BigInteger> orphanBlocks = new HashSet<>();
    private BasicBlockModel bbModel;
    private Memory memory;
    private AddressFactory addressFactory;
    private int defaultSpaceID;

    public AnalysisParser(Program program, TaskMonitor monitor) {
        super(program, monitor);

        this.bbModel = new BasicBlockModel(this.program, false);
        this.memory = this.program.getMemory();
        this.addressFactory = this.program.getAddressFactory();
        this.defaultSpaceID = this.addressFactory.getDefaultAddressSpace().getSpaceID();
    }

    /**
     * Check wether the address specified is being mapped to a portion of the binary itself or not
     * 
     * @param addr The address to check
     * @return True if the address is being mapped from the raw binary, False otherwise
     */
    private boolean isAddrInFile(Address addr) {
        return this.memory.getAddressSourceInfo(addr).getFileOffset() != -1;
    }

    private BlockType getProtoBlockType(FlowType ghidraFlowType) {
        // TODO replace with pattern matching for switch.
        // The feature shouldn't be considered anymore as preview starting from java 21
        // https://openjdk.org/jeps/441
        // TODO add more types in the protobuf
        if (ghidraFlowType.equals(FlowType.CONDITIONAL_JUMP)
                || ghidraFlowType.equals(FlowType.COMPUTED_CALL))
            return BlockType.BLOCK_TYPE_NORMAL;
        else if (ghidraFlowType.equals(FlowType.TERMINATOR))
            return BlockType.BLOCK_TYPE_RET;
        else if (ghidraFlowType.equals(FlowType.COMPUTED_JUMP)
                || ghidraFlowType.equals(FlowType.COMPUTED_CALL_TERMINATOR))
            return BlockType.BLOCK_TYPE_INDJUMP;
        else
            return BlockType.BLOCK_TYPE_ERROR;
    }

    private Function buildFunction(ghidra.program.model.listing.Function ghidraFunc)
            throws CancelledException {
        BigInteger imgBase = this.program.getImageBase().getOffsetAsBigInteger();
        Address funcAddr = ghidraFunc.getEntryPoint();

        if (!funcAddr.isLoadedMemoryAddress())
            throw new RuntimeException(String.format(
                    "Function doesn't seem to be loaded in memory. AddressSpace:  %s  Offset: %d",
                    funcAddr.getAddressSpace().getName(), funcAddr.getOffset()));

        BigInteger funcOffset = funcAddr.getOffsetAsBigInteger().subtract(imgBase);
        boolean isExternal = ghidraFunc.isExternal();

        // A thunk function to an external function is still considered external. This doesn't
        // work recursively to avoid disrupting too much the call graph
        if (ghidraFunc.isThunk() && ghidraFunc.getThunkedFunction(false).isExternal())
            isExternal = true;

        // Create our Function model
        Function function = new Function(funcOffset, this.isAddrInFile(funcAddr), isExternal);

        // Indexes used for building the CFG
        Map<CodeBlock, Integer> bbIndexes = new HashMap<>();
        // Flag to know whether the CodeBlock has a conditional jump. It is used to identify false
        // the false branch of a conditional jump
        Map<CodeBlock, Boolean> bbFlowIsConditional = new HashMap<>();

        // Extract the basic blocks.
        for (var it = this.bbModel.getCodeBlocksContaining(ghidraFunc.getBody(), this.monitor); it
                .hasNext();) {
            CodeBlock basicBlock = it.next();
            BigInteger blockAddr = basicBlock.getFirstStartAddress().getOffsetAsBigInteger();

            // Remove the ones we encounter by navigating functions
            this.orphanBlocks.remove(blockAddr);

            BigInteger blockOffset = blockAddr.subtract(imgBase).subtract(funcOffset);
            BlockType blockType = this.getProtoBlockType(basicBlock.getFlowType());

            // Add the block to the function
            int index = function.addBlock(new Block(blockOffset, blockType));

            bbIndexes.put(basicBlock, index);

            // TODO add missing fields
            // repeated uint32 instructions_index = 3;

            // Check if the basic block contains a conditional jump
            boolean isConditional = false;
            for (var rit = basicBlock.getDestinations(this.monitor); rit.hasNext()
                    && !isConditional;) {
                FlowType flowType = rit.next().getFlowType();
                isConditional |= flowType.isConditional();
            }
            bbFlowIsConditional.put(basicBlock, isConditional);
        }

        // Extract the CFG
        for (var item : bbIndexes.entrySet()) {
            CodeBlock srcBlock = item.getKey();
            Integer srcBlockIndex = item.getValue();

            for (var it = srcBlock.getDestinations(this.monitor); it.hasNext();) {
                CodeBlockReference ref = it.next();
                Integer dstBlockIndex = bbIndexes.get(ref.getDestinationBlock());

                // Add an edge only if it's internal to the function
                if (dstBlockIndex == null)
                    continue;

                FlowType flowType = ref.getFlowType();
                EdgeType edgeType;
                if (flowType.isConditional())
                    edgeType = EdgeType.TYPE_TRUE;
                else if (flowType.isUnConditional() && !flowType.isComputed()
                        && flowType.isFallthrough() && bbFlowIsConditional.get(srcBlock))
                    edgeType = EdgeType.TYPE_FALSE;
                else if (flowType.isUnConditional() && !flowType.isComputed())
                    edgeType = EdgeType.TYPE_UNCONDITIONAL;
                else if (flowType.isUnConditional() && flowType.isComputed())
                    edgeType = EdgeType.TYPE_SWITCH;
                else {
                    LogManager.log(String.format("Unknown flow type %s", flowType.getName()));
                    continue;
                }
                function.addEdge(new Edge(srcBlockIndex, dstBlockIndex, edgeType));
            }
        }

        return function;
    }

    public void analyze() throws CancelledException {
        BigInteger imgBase = this.program.getImageBase().getOffsetAsBigInteger();

        // First collect all the basic blocks.
        // This is used to check whether there are blocks that are not part of any
        // function.
        for (var block : this.bbModel.getCodeBlocks(this.monitor)) {
            // All the basic blocks should be non overlapping and without gaps inside
            var blockAddr = block.getFirstStartAddress();

            if (!blockAddr.isLoadedMemoryAddress())
                throw new RuntimeException(
                        "Error! Found a basic block that is not loaded in memory");
            this.orphanBlocks.add(blockAddr.getOffsetAsBigInteger());
        }

        // Iterate over all the functions
        for (var ghidraFunc : this.program.getListing().getFunctions(true)) {
            var function = this.buildFunction(ghidraFunc);

            this.functions.add(function);
        }

        // Add the "fake" chunks. Those are blocks of instructions that are not part of any function
        for (var addr : this.orphanBlocks) {
            Address fullAddr =
                    this.addressFactory.getAddress(this.defaultSpaceID, addr.longValue());

            var function = new Function(addr.subtract(imgBase), this.isAddrInFile(fullAddr), true);

            // Add a fake basic block if needed (there should always be only one)
            for (CodeBlock block : this.bbModel.getCodeBlocksContaining(fullAddr, this.monitor)) {
                long blockAddr = block.getFirstStartAddress().getOffset();
                Utils.assertLog(blockAddr == addr.longValue(),
                        String.format(
                                "Fake block at 0x%x doesn't start where it is supposed to 0x%x",
                                blockAddr, addr.longValue()));

                // Add the fake block to the function
                function.addBlock(new Block(BigInteger.ZERO, BlockType.BLOCK_TYPE_FAKE, true));
            }

            this.functions.add(function);
        }
    }

    public Collection<Function> getFunctions() {
        return Collections.unmodifiableCollection(this.functions);
    }
}
