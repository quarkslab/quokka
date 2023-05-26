package com.quarkslab.quokka;

import quokka.QuokkaOuterClass.Quokka;
import quokka.QuokkaOuterClass.Quokka.Builder;
import com.quarkslab.quokka.utils.ExporterMode;
import ghidra.program.model.listing.Program;


/**
 * Java implementation of the Quokka writer class for Ghidra using a builder pattern.
 */
public class QuokkaBuilder {
    private final Builder builder = Quokka.newBuilder();

    private final Program program;
    private final ExporterMode exporterMode;

    public QuokkaBuilder(Program program, ExporterMode mode) {
        this.program = program;
        this.exporterMode = mode;
    }
}
