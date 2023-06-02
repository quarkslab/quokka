package com.quarkslab.quokka.models;

import quokka.QuokkaOuterClass.Quokka.DataType;


public class DataComponent {
    private int offset;
    private String name;
    private DataType type;
    private int size;

    public DataComponent(int offset, String name, int size, DataType type) {
        this.offset = offset;
        this.name = name;
        this.size = size;
        this.type = type;
    }

    public int getOffset() {
        return this.offset;
    }

    public String getName() {
        return this.name;
    }

    public int getSize() {
        return this.size;
    }

    public DataType getType() {
        return this.type;
    }
}
