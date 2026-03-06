package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import quokka.QuokkaOuterClass.Quokka;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Phase 7: Export Data[] -- defined data symbols from the Listing.
 * Sorted by (segment_index, segment_offset).
 */
public class DataExporter {

    private DataExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder) {
        Program program = ctx.getProgram();
        SymbolTable symTable = program.getSymbolTable();

        List<DataRecord> records = new ArrayList<>();

        DataIterator dataIter = program.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            if (ctx.getMonitor().isCancelled()) break;

            Data data = dataIter.next();
            Address addr = data.getMinAddress();

            int segIdx = ctx.resolveSegmentIndex(addr);
            if (segIdx < 0) continue; // Skip data outside known segments

            long segOff = ctx.resolveSegmentOffset(addr);
            long fileOff = ctx.resolveFileOffset(addr);
            int typeIdx = ctx.resolveTypeIndex(data.getDataType());
            int size = data.getLength();

            // Get name from symbol table
            String name = "";
            Symbol symbol = symTable.getPrimarySymbol(addr);
            if (symbol != null) {
                name = symbol.getName();
            }

            // Check if uninitialized
            MemoryBlock block = program.getMemory().getBlock(addr);
            boolean notInitialized = block != null && !block.isInitialized();

            records.add(new DataRecord(segIdx, segOff, fileOff,
                    typeIdx, size, name, notInitialized));
        }

        // Sort by (segment_index, segment_offset)
        records.sort(Comparator.<DataRecord, Integer>comparing(d -> d.segIdx)
                .thenComparing(d -> d.segOff));

        for (DataRecord rec : records) {
            Quokka.Data.Builder dataBuilder = Quokka.Data.newBuilder()
                    .setSegmentIndex(rec.segIdx)
                    .setSegmentOffset((int) rec.segOff)
                    .setFileOffset(rec.fileOff)
                    .setTypeIndex(rec.typeIdx)
                    .setSize(rec.size)
                    .setNotInitialized(rec.notInitialized);

            if (rec.name != null && !rec.name.isEmpty()) {
                dataBuilder.setName(rec.name);
            }

            builder.addData(dataBuilder);
        }
    }

    private record DataRecord(int segIdx, long segOff, long fileOff,
            int typeIdx, int size, String name, boolean notInitialized) {}
}
