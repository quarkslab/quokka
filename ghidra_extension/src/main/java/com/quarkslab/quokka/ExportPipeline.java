package com.quarkslab.quokka;

import com.quarkslab.quokka.export.*;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;

import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.XZOutputStream;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringWriter;

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

        // Phase 3b: Type-to-type cross-references
        monitor.setMessage("Quokka: exporting type-to-type xrefs...");
        int typeRefs = TypeExporter.exportTypeToTypeRefs(ctx, builder);
        Msg.info(ExportPipeline.class, "Phase 3b (Type xrefs) complete: "
                + typeRefs + " type-to-type references");

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
        builder.setHeaders(collectHeaders(program, monitor));

        // Phase 8: Compress & serialize (LZMA/XZ)
        monitor.setMessage("Quokka: compressing & writing protobuf...");
        Quokka proto = builder.build();
        int rawSize = proto.getSerializedSize();
        try (FileOutputStream fos = new FileOutputStream(outputFile);
             XZOutputStream xzOut = new XZOutputStream(fos, new LZMA2Options())) {
            proto.writeTo(xzOut);
        }

        long compressedSize = outputFile.length();
        long elapsed = System.currentTimeMillis() - startTime;
        if (rawSize > 0) {
            Msg.info(ExportPipeline.class, String.format(
                    "Compressed %d bytes -> %d bytes (%.1f%%)",
                    rawSize, compressedSize,
                    100.0 * (rawSize - compressedSize) / rawSize));
        }
        Msg.info(ExportPipeline.class, "Quokka export complete in " + elapsed
                + "ms -> " + outputFile.getAbsolutePath()
                + " (" + compressedSize + " bytes)");
    }

    /**
     * Collect C-style type declarations using Ghidra's DataTypeWriter.
     *
     * Produces a complete C header with built-in type preamble, forward
     * declarations, and dependency-ordered type definitions. Equivalent to
     * IDA's {@code print_decls()} with PDF_INCL_DEPS | PDF_DEF_FWD |
     * PDF_DEF_BASE.
     */
    private static String collectHeaders(Program program, TaskMonitor monitor) {
        DataTypeManager dtm = program.getDataTypeManager();
        StringWriter sw = new StringWriter();
        try {
            DataTypeWriter dtw = new DataTypeWriter(dtm, sw);
            dtw.write(dtm, monitor);
        } catch (IOException e) {
            Msg.error(ExportPipeline.class, "Failed to write type headers", e);
        } catch (CancelledException e) {
            Msg.warn(ExportPipeline.class, "Header collection cancelled");
        }
        return sw.toString();
    }
}
