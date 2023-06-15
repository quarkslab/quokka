package com.quarkslab.quokka.parsers;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.TreeMap;
import javax.lang.model.util.ElementScanner14;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import quokka.QuokkaOuterClass.Quokka.Layout.LayoutType;
import com.quarkslab.quokka.models.Layout;


/**
 * Extracts all the layouts from the ghidra analysis.
 * 
 * There shouldn't be overlapping layouts but this is not guaranteed.
 */
public class LayoutParser extends GhidraParser {
    // Parsed fields
    private TreeMap<BigInteger, Layout> layouts = new TreeMap<>();

    public LayoutParser(Program program, TaskMonitor monitor) {
        super(program, monitor);
    }

    public void analyze() throws CancelledException {
        BigInteger imgBase = this.program.getImageBase().getOffsetAsBigInteger();

        // Add all the memory blocks
        for (MemoryBlock block : this.program.getMemory().getBlocks()) {
            // Keep only blocks loaded in memory
            if (!block.getStart().getAddressSpace().isLoadedMemorySpace())
                continue;

            // rebase address
            BigInteger startAddr = block.getStart().getOffsetAsBigInteger().subtract(imgBase);

            // Get layout type
            LayoutType type = LayoutType.LAYOUT_UNK;
            if (block.isExecute())
                type = LayoutType.LAYOUT_CODE;
            else if (block.isRead()) // There is not an easy way of identifying data regions
                type = LayoutType.LAYOUT_DATA;

            // Append layout
            var layout = new Layout(startAddr, block.getSizeAsBigInteger(), type);
            this.layouts.put(layout.getStartAddr(), layout);
        }

        // Add all the gap layouts needed
        List<Layout> toAdd = new ArrayList<>();
        BigInteger prevAddr = BigInteger.ZERO;
        for (var layout : this.layouts.values()) {
            // If there is a gap add a layout to fill the space
            if (prevAddr.compareTo(layout.getStartAddr()) < 0) {
                BigInteger size = layout.getStartAddr().subtract(prevAddr);
                toAdd.add(new Layout(prevAddr, size, LayoutType.LAYOUT_GAP));
            }

            prevAddr = layout.getStartAddr().add(layout.getSize());
        }

        for (var layout : toAdd)
            this.layouts.put(layout.getStartAddr(), layout);
    }

    public Collection<Layout> getAll() {
        return Collections.unmodifiableCollection(this.layouts.values());
    }
}
