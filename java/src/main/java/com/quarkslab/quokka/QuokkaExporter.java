package com.quarkslab.quokka;

import com.quarkslab.quokka.utils.EnumOption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.DomainObjectService;
import ghidra.app.util.OptionException;
import ghidra.app.util.Option;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.app.util.exporter.ExporterException;

/**
 * Exports Ghidra diassembly analysis into quokka protobuf format.
 */
public class QuokkaExporter extends Exporter {

    // Display name that appears in the export dialog.
    private static final String QUOKKA_FORMAT_DISPLAY_NAME = "Quokka";

    private static final String QUOKKA_FILE_EXTENSION = "quokka";

    // Option names
    private static final String EXPORTER_MODE_OPT = "Exporter mode";

    // The exporter mode (light, normal, full)
    private ExporterMode exporterMode;

    // Stringized version number allowing for scriptable update.
    public static final String QUOKKA_VERSION = "0.5.1";

    public static final String QUOKKA_COPYRIGHT =
            "Quokka " + QUOKKA_VERSION + " (c)2022-2023 Quarkslab";

    public QuokkaExporter() {
        super(QUOKKA_FORMAT_DISPLAY_NAME, QUOKKA_FILE_EXTENSION, null);
        this.log.appendMsg(QUOKKA_COPYRIGHT);
    }

    @Override
    public boolean export(File file, DomainObject domainObj, AddressSetView addrSet,
            TaskMonitor monitor) throws ExporterException, IOException {
        if (!(domainObj instanceof Program)) {
            this.log.appendMsg("Unsupported type: " + domainObj.getClass().getName());
            return false;
        }
        final var program = (Program) domainObj;

        // Enable cancellability
        monitor.setCancelEnabled(true);
        try {
            final var builder = new QuokkaBuilder(program, this.exporterMode, monitor);
            final Quokka proto = builder.build();

            monitor.setMessage("Writing Quokka exported file");
            try (final var outputStream = new FileOutputStream(file)) {
                proto.writeTo(outputStream);
            } catch (IOException e) {
                this.log.appendMsg(String.format("[!] IO error while writing to the output file %s", file.getAbsolutePath()));
                return false;
            }
        } catch (final CancelledException e) {
            return false;
        }

        return true;
    }

    @Override
    @SuppressWarnings("JdkImmutableCollections")
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        return List.of(new EnumOption(EXPORTER_MODE_OPT, ExporterMode.MODE_NORMAL,
                ExporterMode.class, null));
    }

    @Override
    public void setOptions(List<Option> options) throws OptionException {
        for (final var option : options) {
            switch (option.getName()) {
                case EXPORTER_MODE_OPT:
                    this.exporterMode = (ExporterMode) option.getValue();
                    break;
                default:
                    this.log.appendMsg("Warning, ignoring unknown option");
                    break;
            }
            break;
        }
    }
}
