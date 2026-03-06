package com.quarkslab.quokka;

import ghidra.app.util.DomainObjectService;
import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.app.util.exporter.Exporter;
import ghidra.app.util.exporter.ExporterException;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import quokka.QuokkaOuterClass.Quokka;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Ghidra GUI entry point: File > Export > Quokka.
 * Extends Ghidra's Exporter interface, delegates to ExportPipeline.
 */
public class QuokkaExporter extends Exporter {

    private Quokka.ExporterMeta.Mode mode =
            Quokka.ExporterMeta.Mode.MODE_LIGHT;

    public QuokkaExporter() {
        super("Quokka", "quokka", null);
    }

    @Override
    public List<Option> getOptions(DomainObjectService domainObjectService) {
        List<Option> options = new ArrayList<>();
        options.add(new Option("Export Mode", "LIGHT"));
        return options;
    }

    @Override
    public void setOptions(List<Option> options) throws OptionException {
        for (Option opt : options) {
            if ("Export Mode".equals(opt.getName())) {
                String val = (String) opt.getValue();
                if ("SELF_CONTAINED".equalsIgnoreCase(val)) {
                    mode = Quokka.ExporterMeta.Mode.MODE_SELF_CONTAINED;
                } else {
                    mode = Quokka.ExporterMeta.Mode.MODE_LIGHT;
                }
            }
        }
    }

    @Override
    public boolean export(File file, DomainObject domainObj,
            AddressSetView addrSet, TaskMonitor monitor)
            throws ExporterException, IOException {
        if (!(domainObj instanceof Program)) {
            log.appendMsg("Quokka can only export Program objects");
            return false;
        }

        try {
            ExportPipeline.export((Program) domainObj, file, mode, monitor);
            return true;
        } catch (Exception e) {
            log.appendMsg("Quokka export failed: " + e.getMessage());
            log.appendException(e);
            return false;
        }
    }
}
