package com.quarkslab.quokka.models;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import quokka.QuokkaOuterClass.Quokka.Structure.StructureType;


public class CompositeData {
    private String name;
    private int size;
    private StructureType type;
    private List<DataComponent> components = new ArrayList<>();

    public CompositeData(String name, int size, StructureType type) {
        this.name = name;
        if (size == -1)
            this.size = 0;
        else
            this.size = size;
        this.type = type;
    }

    public String getName() {
        return this.name;
    }

    public int getSize() {
        return this.size;
    }

    public StructureType getType() {
        return this.type;
    }

    public List<DataComponent> getComponents() {
        return Collections.unmodifiableList(this.components);
    }

    public boolean isFixedSize() {
        return this.size > 0;
    }

    public void addComponent(DataComponent component) {
        this.components.add(component);
    }
}
