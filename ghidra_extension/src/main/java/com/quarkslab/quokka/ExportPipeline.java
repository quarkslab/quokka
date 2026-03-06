package com.quarkslab.quokka;

import com.quarkslab.quokka.export.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;

import java.io.File;
import java.io.FileOutputStream;
import java.util.Iterator;

/**
 * Orchestrates the 8-phase export pipeline.
 * Public API entry point for both GUI and headless export.
 */
public class ExportPipeline {

    private ExportPipeline() {}

    /**
     * Export a Ghidra Program to a .quokka protobuf file.
     *
     * @param program    the Ghidra Program to export
     * @param outputFile the output .quokka file path
     * @param mode       export mode (MODE_LIGHT or MODE_SELF_CONTAINED)
     * @param monitor    task monitor for progress and cancellation
     * @throws Exception if export fails
     */
    public static void export(Program program, File outputFile,
            Quokka.ExporterMeta.Mode mode, TaskMonitor monitor)
            throws Exception {

        ExportContext ctx = new ExportContext(program, outputFile, mode, monitor);
        Quokka.Builder builder = Quokka.newBuilder();

        long startTime = System.currentTimeMillis();

        // Phase 1: Metadata
        monitor.setMessage("Quokka: exporting metadata...");
        MetaExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 1 (Meta) complete");

        // Phase 2: Segments (must come before functions/data for index resolution)
        monitor.setMessage("Quokka: exporting segments...");
        SegmentExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 2 (Segments) complete: "
                + ctx.getSegments().size() + " segments");

        // Phase 3: Types
        monitor.setMessage("Quokka: exporting types...");
        TypeExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 3 (Types) complete: "
                + builder.getTypesCount() + " types");

        // Phase 4: Functions
        monitor.setMessage("Quokka: exporting functions...");
        FunctionExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 4 (Functions) complete: "
                + builder.getFunctionsCount() + " functions");

        // Phase 5: References
        monitor.setMessage("Quokka: exporting references...");
        ReferenceExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 5 (References) complete: "
                + builder.getReferencesCount() + " references");

        // Phase 6: Layout
        monitor.setMessage("Quokka: exporting layout...");
        LayoutExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 6 (Layout) complete: "
                + builder.getLayoutCount() + " regions");

        // Phase 7: Data
        monitor.setMessage("Quokka: exporting data...");
        DataExporter.export(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 7 (Data) complete: "
                + builder.getDataCount() + " data entries");

        // Headers: collect C-style type declarations
        monitor.setMessage("Quokka: collecting headers...");
        builder.setHeaders(collectHeaders(program));

        // Phase 8: Serialize
        monitor.setMessage("Quokka: writing protobuf...");
        Quokka proto = builder.build();
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            proto.writeTo(fos);
        }

        long elapsed = System.currentTimeMillis() - startTime;
        Msg.info(ExportPipeline.class, "Quokka export complete in " + elapsed
                + "ms -> " + outputFile.getAbsolutePath()
                + " (" + outputFile.length() + " bytes)");
    }

    /**
     * Collect C-style type declarations from the DataTypeManager.
     */
    private static String collectHeaders(Program program) {
        DataTypeManager dtm = program.getDataTypeManager();
        StringBuilder sb = new StringBuilder();
        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            String repr = dt.toString();
            if (repr != null && !repr.isEmpty()) {
                sb.append(repr).append('\n');
            }
        }
        return sb.toString();
    }
}
