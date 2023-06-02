package com.quarkslab.quokka.models;

import java.math.BigInteger;
import quokka.QuokkaOuterClass.Quokka.DataType;


public class Data {
    private BigInteger address;
    private int size;
    private boolean isInitialized;
    private DataType type;
    private String name;

    public Data(BigInteger address, int size, DataType type, boolean isInitialized, String name) {
        this.address = address;
        this.size = size;
        this.isInitialized = isInitialized;
        this.type = type;
        this.name = name;
    }

    public BigInteger getAddr() {
        return this.address;
    }

    public long getAddrAsLong() {
        return this.address.longValue();
    }

    public int getSize() {
        return this.size;
    }

    public boolean isInitialized() {
        return this.isInitialized;
    }

    public DataType getType() {
        return this.type;
    }

    public String getName() {
        return this.name;
    }

    public boolean isFixedSize() {
        return (this.type != DataType.TYPE_UNK);
    }
}
