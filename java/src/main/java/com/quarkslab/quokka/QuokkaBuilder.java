package com.quarkslab.quokka;

import com.quarkslab.quokka.models.Layout;
import com.quarkslab.quokka.parsers.FileMetadataParser;
import com.quarkslab.quokka.parsers.LayoutParser;
import com.quarkslab.quokka.parsers.DataParser;
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

    /**
     * Load in the protobuf builder all the metadata
     */
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

    /**
     * Load in the protobuf builder the layouts.
     * 
     * @see Layout
     */
    private void exportLayout() {
        monitor.setIndeterminate(true);
        monitor.setMessage("Exporting layout");

        var layoutParser = new LayoutParser(this.program);
        layoutParser.analyze();

        for (var layout : layoutParser.getAll()) {
            var layoutBuilder = this.builder.addLayoutBuilder();

            // Set protobuf fields
            layoutBuilder.getAddressRangeBuilder().setStartAddress(layout.getStartAddrAsLong())
                    .setSize(layout.getSizeAsLong());
            layoutBuilder.setLayoutType(layout.getType());
        }
    }

    /**
     * Load in the protobuf builder all the data objects defined by ghidra
     */
    private void exportData() {
        monitor.setIndeterminate(true);
        monitor.setMessage("Exporting data");

        var dataParser = new DataParser(this.program);
        dataParser.analyze();

        for (var data : dataParser.getAll()) {
            var dataBuilder = this.builder.addDataBuilder();

            // Set protobuf fields
            dataBuilder.setOffset(data.getAddrAsLong()).setNotInitialized(!data.isInitialized())
                    .setType(data.getType());
            if (data.isFixedSize())
                dataBuilder.setNoSize(true);
            else
                dataBuilder.setSize(data.getSize());
        }
    }

    /**
     * Build and return the protobuf message.
     * 
     * @return Quokka The protobuf message
     * @throws CancelledException
     */
    public Quokka build() throws CancelledException {
        this.exportMeta();

        this.exportLayout();

        this.exportData();

        // ExportSegments(&quokka_protobuf);
        // ExportEnumAndStructures(&quokka_protobuf);

        // replace_wait_box("quokka: exporting layout");
        // ExportLayout(&quokka_protobuf);

        return this.builder.build();
    }
}
