package com.quarkslab.quokka;

import com.quarkslab.quokka.parsers.FileMetadataParser;
import quokka.QuokkaOuterClass.Quokka;
import quokka.QuokkaOuterClass.Quokka.Builder;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


/**
 * Java implementation of the Quokka writer class for Ghidra using a builder pattern.
 */
public class QuokkaBuilder {
    private final Builder builder = Quokka.newBuilder();

    private final Program program;
    private final ExporterMode exporterMode;

    private TaskMonitor monitor;

    public QuokkaBuilder(Program program, ExporterMode mode, TaskMonitor taskMonitor) {
        this.program = program;
        this.exporterMode = mode;
        this.monitor = taskMonitor;

        this.monitor.setMessage(String.format("Exporter set in %s", this.exporterMode.toString()));
    }

    private void exportMeta() {
        monitor.setIndeterminate(true);
        monitor.setMessage("Exporting meta data");

        // exporter_meta
        this.builder.getExporterMetaBuilder().setVersion(QuokkaExporter.QUOKKA_VERSION)
                .setMode(this.exporterMode.toProto());

        // File metadata
        var metaParser = new FileMetadataParser(this.program);
        metaParser.analyze();

        var meta = this.builder.getMetaBuilder();
        meta.setExecutableName(metaParser.getExecName());
        meta.setIsa(metaParser.getArch());
        meta.setCompiler(metaParser.getCompiler());
        meta.setCallingConvention(metaParser.getCallConvention());
        meta.getHashBuilder().setHashType(metaParser.getHashType())
                .setHashValue(metaParser.getHash());
        meta.setEndianess(metaParser.getEndianess());
        meta.setAddressSize(metaParser.getAddresSize());
        meta.setBaseAddr(metaParser.getBaseAddr());
    }

    public Quokka build() throws CancelledException {
        this.exportMeta();

        // ExportMeta(&quokka_protobuf);

        // ExportSegments(&quokka_protobuf);
        // ExportEnumAndStructures(&quokka_protobuf);

        // replace_wait_box("quokka: exporting layout");
        // ExportLayout(&quokka_protobuf);

        return this.builder.build();
    }
}
