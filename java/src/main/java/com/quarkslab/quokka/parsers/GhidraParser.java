package com.quarkslab.quokka.parsers;

import ghidra.program.model.listing.Program;


/**
 * Retrieves from the ghidra analysis all the the information needed.
 */
public abstract class GhidraParser {
    protected Program program;

    public GhidraParser(Program program) {
        this.program = program;
    }

    /**
     * Run the analysis, extract all the informations needed from Ghidra
     */
    abstract void analyze();
}
