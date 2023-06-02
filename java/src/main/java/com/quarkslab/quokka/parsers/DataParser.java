package com.quarkslab.quokka.parsers;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.swing.text.html.HTMLDocument.HTMLReader.IsindexAction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.util.DefinedDataIterator;
import quokka.QuokkaOuterClass.Quokka.DataType;
import com.quarkslab.quokka.models.Data;


/**
 * Retrieves from ghidra all the data objects identified
 */
public class DataParser {
    private Program program;

    // Fields
    private Set<Data> dataSet = new HashSet<>();

    public DataParser(Program program) {
        this.program = program;
    }

    /**
     * Run the analysis, extract all the informations needed from Ghidra
     */
    public void analyze() {
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
            // TODO replace with pattern matching for switch.
            // The feature shouldn't be considered anymore as preview starting from java 21
            // https://openjdk.org/jeps/441
            // TODO implement all the possible data types
            // https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataType.html
            DataType type;
            var ghidraDataType = data.getDataType();
            if (ghidraDataType instanceof ByteDataType) {
                type = DataType.TYPE_B;
            } else {
                type = DataType.TYPE_UNK;
            }

            // Check data size. It cannot be undefined (-1)
            int size = data.getLength();
            assert size != -1;

            // Add the data object
            this.dataSet.add(
                    new Data(address, size, type, data.isInitializedMemory(), data.getLabel()));
        }
    }

    public Collection<Data> getAll() {
        return Collections.unmodifiableCollection(this.dataSet);
    }
}
