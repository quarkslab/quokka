package com.quarkslab.quokka.parsers;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import ghidra.program.model.listing.Program;
import quokka.QuokkaOuterClass.Quokka.Structure.StructureType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import com.quarkslab.quokka.models.CompositeData;
import com.quarkslab.quokka.models.DataComponent;
import com.quarkslab.quokka.utils.Utils;

/**
 * Retrieves from ghidra all the composite data objects. The composite data
 * formats are usually
 * structs and union.
 * 
 * In this case quokka considers enum to be composite data types.
 */
public class CompositeDataParser extends GhidraParser {
    private Set<CompositeData> compositeData = new HashSet<>();

    public CompositeDataParser(Program program, TaskMonitor monitor) {
        super(program, monitor);
    }

    public void analyze() throws CancelledException {
        for (var it = this.program.getDataTypeManager().getAllDataTypes(); it.hasNext();) {
            DataType dataType = it.next();
            StructureType type;
            // TODO replace with pattern matching for switch.
            // The feature shouldn't be considered anymore as preview starting from java 21
            // https://openjdk.org/jeps/441
            if (dataType instanceof Structure) {
                type = StructureType.TYPE_STRUCT;
            } else if (dataType instanceof Union) {
                type = StructureType.TYPE_UNION;
            } else if (dataType instanceof Enum) {
                type = StructureType.TYPE_ENUM;
            } else if (dataType instanceof Composite) {
                // Probably never happening
                type = StructureType.TYPE_UNK;
            } else {
                // Ignore the non composite data types
                continue;
            }

            // Create the composite data object
            var data = new CompositeData(dataType.getName(), dataType.getLength(), type);

            // Enums aren't technically a composite data structure
            if (dataType instanceof Composite compositeDataType) {
                for (DataTypeComponent component : compositeDataType.getComponents()) {
                    data.addComponent(new DataComponent(component.getOffset(),
                            component.getFieldName(), component.getLength(),
                            Utils.getDataTypeFromGhidra(component.getDataType())));
                }
            }

            // Add it to the collection
            this.compositeData.add(data);
        }
    }

    public Collection<CompositeData> getAll() {
        return Collections.unmodifiableCollection(this.compositeData);
    }
}
