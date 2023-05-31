package com.quarkslab.quokka.models;

import java.math.BigInteger;
import quokka.QuokkaOuterClass.Quokka.Layout.LayoutType;


/**
 * A layout is a representation of a contiguous block of memory (or a segment in some cases) tagged
 * by a type (code, data, etc...). This is just a representation of how ghidra loaded the binary in
 * memory, remember there might be some differences with a real loader.
 * 
 * There is a special type of layout called <strong>GAP</strong> that identifies a gap between two
 * memory blocks.
 */
public class Layout {
    private BigInteger startAddr;
    private BigInteger size;
    private LayoutType type;

    public Layout(BigInteger startAddr, BigInteger size, LayoutType type) {
        this.startAddr = startAddr;
        this.size = size;
        this.type = type;
    }

    public BigInteger getStartAddr() {
        return this.startAddr;
    }

    public BigInteger getSize() {
        return this.size;
    }

    public LayoutType getType() {
        return this.type;
    }

    public long getStartAddrAsLong() {
        return this.startAddr.longValue();
    }

    public long getSizeAsLong() {
        return this.size.longValue();
    }
}
