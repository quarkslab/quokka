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
    private List<Edge> edges = new ArrayList<>();

    public Function(BigInteger addr, boolean isInFile, boolean isFake) {
        this.addr = addr;
        this.isFake = isFake;
        this.isInFile = isInFile;
    }

    public Function(BigInteger addr, boolean isInFile) {
        this(addr, isInFile, false);
    }

    /**
     * Add a Block to the function and returns its index
     * 
     * @param Block The block to add
     * @return The index of the block just added
     */
    public int addBlock(Block block) {
        this.blocks.add(block);
        return this.blocks.size() - 1;
    }

    public void addEdge(Edge edge) {
        this.edges.add(edge);
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

    public List<Edge> getEdges() {
        return Collections.unmodifiableList(this.edges);
    }
}
