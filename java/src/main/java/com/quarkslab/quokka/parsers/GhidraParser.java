package com.quarkslab.quokka.parsers;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

/**
 * Retrieves from the ghidra analysis all the the information needed.
 */
public abstract class GhidraParser {
    protected Program program;
    protected TaskMonitor monitor;

    public GhidraParser(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    /**
     * Run the analysis, extract all the informations needed from Ghidra
     * 
     * @throws CacelledException
     */
    abstract void analyze() throws CancelledException;
}
