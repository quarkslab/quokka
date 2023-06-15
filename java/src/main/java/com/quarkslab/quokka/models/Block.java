package com.quarkslab.quokka.models;

import java.math.BigInteger;
import quokka.QuokkaOuterClass.Quokka.FunctionChunk.Block.BlockType;

public class Block {
    private BigInteger offset;
    private boolean isFake;
    private BlockType type;

    public Block(BigInteger offset, BlockType type, boolean isFake) {
        this.offset = offset;
        this.isFake = false;
        this.type = type;
    }

    public Block(BigInteger offset, BlockType type) {
        this(offset, type, false);
    }

    public BigInteger getOffset() {
        return this.offset;
    }

    public long getOffsetAsLong() {
        return this.offset.longValue();
    }

    public boolean isFake() {
        return this.isFake;
    }

    public BlockType getType() {
        return this.type;
    }
}
