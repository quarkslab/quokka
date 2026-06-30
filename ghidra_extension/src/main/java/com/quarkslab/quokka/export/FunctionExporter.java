package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.util.BlockTypeMapper;
import com.quarkslab.quokka.util.FunctionTypeMapper;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;

import java.util.*;

/**
 * Phase 4: Export Function[] with Block[] and CFG Edge[].
 * Uses SimpleBlockModel (not BasicBlockModel) to match IDA behavior.
 */
public class FunctionExporter {

    private FunctionExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder)
            throws Exception {
        Program program = ctx.getProgram();
        FunctionManager funcMgr = program.getFunctionManager();
        SimpleBlockModel blockModel = new SimpleBlockModel(program);
        TaskMonitor monitor = ctx.getMonitor();
        DecompInterface decompiler = null;

        // Collect all functions, sort by entry VA
        List<Function> functions = new ArrayList<>();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            functions.add(funcIter.next());
        }
        functions.sort(Comparator.comparing(f -> f.getEntryPoint()));

        try {
            if (ctx.isDecompilationEnabled()) {
                Msg.info(FunctionExporter.class,
                        "Initializing Ghidra decompiler for function export");
                decompiler = new DecompInterface();
                decompiler.setOptions(new DecompileOptions());
                decompiler.toggleCCode(true);
                decompiler.toggleSyntaxTree(false);
                decompiler.setSimplificationStyle("decompile");
                if (!decompiler.openProgram(program)) {
                    Msg.warn(FunctionExporter.class,
                            "Unable to initialize Ghidra decompiler: "
                            + decompiler.getLastMessage());
                    decompiler.dispose();
                    decompiler = null;
                } else {
                    Msg.info(FunctionExporter.class,
                            "Ghidra decompiler initialized");
                }
            }

            int processed = 0;
            for (Function func : functions) {
                if (monitor.isCancelled()) break;
                if (processed % 100 == 0) {
                    Msg.info(FunctionExporter.class, "Exporting function "
                            + processed + "/" + functions.size() + ": "
                            + func.getName() + " @ " + func.getEntryPoint());
                }

                Quokka.Function.Builder funcBuilder = Quokka.Function.newBuilder();

                // Location
                Address entry = func.getEntryPoint();
                int segIdx = ctx.resolveSegmentIndex(entry);
                if (segIdx < 0) {
                    // External functions may not have a segment
                    if (!func.isExternal()) {
                        Msg.warn(FunctionExporter.class,
                                "Cannot resolve segment for function: " + func.getName()
                                + " at " + entry);
                    }
                    funcBuilder.setSegmentIndex(0);
                    funcBuilder.setSegmentOffset(0);
                    funcBuilder.setFileOffset(-1);
                } else {
                    funcBuilder.setSegmentIndex(segIdx);
                    funcBuilder.setSegmentOffset(
                            (int) ctx.resolveSegmentOffset(entry));
                    funcBuilder.setFileOffset(ctx.resolveFileOffset(entry));
                }

                // Type
                funcBuilder.setFunctionType(FunctionTypeMapper.map(func));

                // Names
                funcBuilder.setName(func.getName());
                Symbol symbol = func.getSymbol();
                if (symbol != null) {
                    String mangledName = symbol.getName();
                    if (!mangledName.equals(func.getName())) {
                        funcBuilder.setMangledName(mangledName);
                    }
                }

                // Prototype
                String prototype = func.getPrototypeString(false, false);
                if (prototype != null) {
                    funcBuilder.setPrototype(prototype);
                }

                // Exported symbol detection
                funcBuilder.setIsExported(
                        program.getSymbolTable().isExternalEntryPoint(entry));

                if (decompiler != null && !func.isExternal()) {
                    String cCode = decompileFunction(decompiler, func, monitor);
                    if (cCode != null && !cCode.isEmpty()) {
                        funcBuilder.setDecompiledCode(cCode);
                    }
                }

                // Blocks and edges (only for non-external functions with bodies)
                if (!func.isExternal() && func.getBody() != null
                        && !func.getBody().isEmpty()) {
                    exportBlocksAndEdges(ctx, builder, program, func, blockModel,
                            funcBuilder, monitor);
                }

                builder.addFunctions(funcBuilder);
                processed++;
            }
        } finally {
            if (decompiler != null) {
                decompiler.closeProgram();
                decompiler.dispose();
            }
        }
    }

    private static void exportBlocksAndEdges(ExportContext ctx,
            Quokka.Builder builder, Program program, Function func,
            SimpleBlockModel blockModel,
            Quokka.Function.Builder funcBuilder, TaskMonitor monitor)
            throws Exception {

        // Get blocks within function body using SimpleBlockModel
        CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(
                func.getBody(), monitor);

        // Collect blocks
        List<CodeBlock> blocks = new ArrayList<>();
        while (blockIter.hasNext()) {
            blocks.add(blockIter.next());
        }

        // Sort by (segment_index, segment_offset)
        blocks.sort(Comparator.<CodeBlock, Integer>comparing(
                        b -> ctx.resolveSegmentIndex(b.getMinAddress()))
                .thenComparing(b -> ctx.resolveSegmentOffset(b.getMinAddress())));

        // Map block start address -> index within function
        Map<Address, Integer> blockIndexMap = new HashMap<>();
        for (int i = 0; i < blocks.size(); i++) {
            blockIndexMap.put(blocks.get(i).getMinAddress(), i);
        }

        // Write blocks
        Listing listing = program.getListing();
        for (CodeBlock block : blocks) {
            Quokka.Block.Builder blockBuilder = Quokka.Block.newBuilder();
            Address start = block.getMinAddress();

            int segIdx = ctx.resolveSegmentIndex(start);
            if (segIdx >= 0) {
                blockBuilder.setSegmentIndex(segIdx);
                blockBuilder.setSegmentOffset(
                        (int) ctx.resolveSegmentOffset(start));
                blockBuilder.setFileOffset(ctx.resolveFileOffset(start));
            } else {
                blockBuilder.setSegmentIndex(0);
                blockBuilder.setSegmentOffset(0);
                blockBuilder.setFileOffset(-1);
            }

            blockBuilder.setBlockType(
                    BlockTypeMapper.map(block, program, monitor));

            // Block size
            long blockSize = block.getMaxAddress().subtract(start) + 1;
            blockBuilder.setSize((int) blockSize);

            // Count instructions in block. In SELF_CONTAINED mode, also export
            // instruction/operand tables so Python can avoid runtime disassembly.
            int instrCount = 0;
            InstructionIterator instrIter = listing.getInstructions(block, true);
            while (instrIter.hasNext()) {
                Instruction instruction = instrIter.next();
                instrCount++;
                if (ctx.getMode() == Quokka.ExporterMeta.Mode.MODE_SELF_CONTAINED) {
                    blockBuilder.addInstructionIndex(
                            exportInstruction(builder, program, instruction));
                }
            }
            blockBuilder.setNInstr(instrCount);

            // is_thumb: check ARM Thumb mode
            blockBuilder.setIsThumb(isThumbMode(program, start));

            funcBuilder.addBlocks(blockBuilder);
        }

        // Write CFG edges
        for (int srcIdx = 0; srcIdx < blocks.size(); srcIdx++) {
            CodeBlock srcBlock = blocks.get(srcIdx);
            CodeBlockReferenceIterator destIter =
                    srcBlock.getDestinations(monitor);

            List<int[]> pendingEdges = new ArrayList<>();
            while (destIter.hasNext()) {
                CodeBlockReference ref = destIter.next();
                Address destAddr = ref.getDestinationBlock()
                        .getFirstStartAddress();
                Integer dstIdx = blockIndexMap.get(destAddr);
                if (dstIdx != null) {
                    pendingEdges.add(new int[]{srcIdx, dstIdx});
                }
            }

            // Edge type based on out-degree (matching IDA behavior)
            Quokka.EdgeType edgeType = getEdgeType(pendingEdges.size());
            for (int[] edge : pendingEdges) {
                funcBuilder.addEdges(Quokka.Function.Edge.newBuilder()
                        .setEdgeType(edgeType)
                        .setSource(edge[0])
                        .setDestination(edge[1])
                        .setUserDefined(false));
            }
        }
    }

    private static int exportInstruction(Quokka.Builder builder, Program program,
            Instruction instruction) {
        Quokka.Instruction.Builder instrBuilder = Quokka.Instruction.newBuilder();
        instrBuilder.setSize(instruction.getLength());
        instrBuilder.setMnemonicIndex(
                internString(builder.getMnemonicsList(),
                        instruction.getMnemonicString(),
                        builder::addMnemonics));
        instrBuilder.setIsThumb(isThumbMode(program, instruction.getAddress()));

        for (int opIdx = 0; opIdx < instruction.getNumOperands(); opIdx++) {
            instrBuilder.addOperandIndex(
                    exportOperand(builder, instruction, opIdx));
        }

        int protoIndex = builder.getInstructionsCount();
        builder.addInstructions(instrBuilder);
        return protoIndex;
    }

    private static int exportOperand(Quokka.Builder builder,
            Instruction instruction, int opIdx) {
        String operandText = instruction.getDefaultOperandRepresentation(opIdx);
        if (operandText == null) {
            operandText = "";
        }

        Quokka.Operand.Builder operandBuilder = Quokka.Operand.newBuilder()
                .setOperandStringIndex(
                        internString(builder.getOperandStringsList(),
                                operandText,
                                builder::addOperandStrings))
                .setAccess(accessMask(instruction.getOperandRefType(opIdx)));

        Object[] opObjects = instruction.getOpObjects(opIdx);
        Object primary = opObjects.length > 0 ? opObjects[0] : null;
        if (primary instanceof Register) {
            operandBuilder
                    .setType(Quokka.Operand.OperandType.OPERAND_REGISTER)
                    .setRegisterIndex(((Register) primary).getName());
        } else if (primary instanceof Scalar) {
            operandBuilder
                    .setType(Quokka.Operand.OperandType.OPERAND_IMMEDIATE)
                    .setValue(((Scalar) primary).getSignedValue());
        } else if (primary instanceof Address) {
            operandBuilder
                    .setType(Quokka.Operand.OperandType.OPERAND_MEMORY)
                    .setAddress(((Address) primary).getOffset());
        } else {
            operandBuilder
                    .setType(Quokka.Operand.OperandType.OPERAND_OTHER)
                    .setOther(operandText);
        }

        int protoIndex = builder.getOperandsCount();
        builder.addOperands(operandBuilder);
        return protoIndex;
    }

    private interface StringAppender {
        void add(String value);
    }

    private static int internString(List<String> values, String value,
            StringAppender appender) {
        int existing = values.indexOf(value);
        if (existing >= 0) {
            return existing;
        }
        appender.add(value);
        return values.size();
    }

    private static int accessMask(RefType refType) {
        if (refType == null) {
            return 0;
        }
        int access = 0;
        if (refType.isRead()) {
            access |= 1;
        }
        if (refType.isWrite()) {
            access |= 2;
        }
        return access;
    }

    private static String decompileFunction(DecompInterface decompiler,
            Function func, TaskMonitor monitor) {
        try {
            DecompileResults results = decompiler.decompileFunction(func,
                    5, monitor);
            if (results != null && results.decompileCompleted()
                    && results.getDecompiledFunction() != null) {
                return results.getDecompiledFunction().getC();
            }
        } catch (Exception e) {
            Msg.warn(FunctionExporter.class,
                    "Failed to decompile " + func.getName() + ": "
                    + e.getMessage());
        }
        return null;
    }

    private static Quokka.EdgeType getEdgeType(int outDegree) {
        switch (outDegree) {
            case 0: return Quokka.EdgeType.EDGE_UNKNOWN;
            case 1: return Quokka.EdgeType.EDGE_JUMP_UNCOND;
            case 2: return Quokka.EdgeType.EDGE_JUMP_COND;
            default: return Quokka.EdgeType.EDGE_JUMP_INDIR;
        }
    }

    private static boolean isThumbMode(Program program, Address addr) {
        String procName = program.getLanguage().getProcessor().toString();
        if (!"ARM".equals(procName) && !"AARCH64".equals(procName)) {
            return false;
        }
        ghidra.program.model.lang.Register tmode =
                program.getRegister("TMode");
        if (tmode == null) {
            return false;
        }
        ghidra.program.model.lang.RegisterValue rv =
                program.getProgramContext().getRegisterValue(tmode, addr);
        return rv != null
                && rv.getUnsignedValueIgnoreMask().intValue() == 1;
    }
}
