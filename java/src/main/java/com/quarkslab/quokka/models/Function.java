package com.quarkslab.quokka.models;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Function {
    private BigInteger addr;
    private boolean isFake;
    private boolean isInFile;
    private List<Block> blocks = new ArrayList<>();

    public Function(BigInteger addr, boolean isInFile, boolean isFake) {
        this.addr = addr;
        this.isFake = isFake;
        this.isInFile = isInFile;
    }

    public Function(BigInteger addr, boolean isInFile) {
        this(addr, isInFile, false);
    }

    public void addBlock(Block block) {
        this.blocks.add(block);
    }

    public BigInteger getAddr() {
        return this.addr;
    }

    public boolean isFake() {
        return this.isFake;
    }

    public boolean isInFile() {
        return this.isInFile;
    }

    public long getAddrAsLong() {
        return this.addr.longValue();
    }

    public List<Block> getBlocks() {
        return Collections.unmodifiableList(this.blocks);
    }
}
