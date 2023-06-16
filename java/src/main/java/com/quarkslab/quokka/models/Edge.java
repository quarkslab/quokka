package com.quarkslab.quokka.models;

import quokka.QuokkaOuterClass.Quokka.Edge.EdgeType;

public class Edge {
    private int srcBlockIndex;
    private int dstBlockIndex;
    private EdgeType type;

    public Edge(int srcBlockIndex, int dstBlockIndex, EdgeType type) {
        this.srcBlockIndex = srcBlockIndex;
        this.dstBlockIndex = dstBlockIndex;
        this.type = type;
    }

    public int getSrcBlockIndex() {
        return this.srcBlockIndex;
    }

    public int getDstBlockIndex() {
        return this.dstBlockIndex;
    }

    public EdgeType getType() {
        return this.type;
    }
}
