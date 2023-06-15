package com.quarkslab.quokka.parsers;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.swing.text.html.HTMLDocument.HTMLReader.IsindexAction;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import quokka.QuokkaOuterClass.Quokka.DataType;
import com.quarkslab.quokka.models.Data;
import com.quarkslab.quokka.utils.Utils;


/**
 * Retrieves from ghidra all the data objects identified
 */
public class DataParser extends GhidraParser {
    // Fields
    private Set<Data> dataSet = new HashSet<>();

    public DataParser(Program program, TaskMonitor monitor) {
        super(program, monitor);
    }

    public void analyze() throws CancelledException {
        BigInteger imgBase = this.program.getImageBase().getOffsetAsBigInteger();

        // Since java doesn't support class name aliases it's better to use type inference
        // instead of the longer ghidra.program.model.listing.Data
        for (var data : this.program.getListing().getData(true)) {
            // Keep only data loaded in memory
            if (!data.getAddress().getAddressSpace().isLoadedMemorySpace())
                continue;

            // rebase address
            BigInteger address = data.getAddress().getOffsetAsBigInteger().subtract(imgBase);

            // Get the data type
            DataType type = Utils.getDataTypeFromGhidra(data.getDataType());

            // Check data size. It cannot be undefined (-1)
            int size = data.getLength();
            Utils.assertLog(size != -1, "Found some data with unknown size");

            // Add the data object
            this.dataSet.add(
                    new Data(address, size, type, data.isInitializedMemory(), data.getLabel()));
        }
    }

    public Collection<Data> getAll() {
        return Collections.unmodifiableCollection(this.dataSet);
    }
}
