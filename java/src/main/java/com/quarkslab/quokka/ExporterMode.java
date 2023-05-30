package com.quarkslab.quokka;

import javax.management.RuntimeErrorException;
import quokka.QuokkaOuterClass.Quokka.ExporterMeta.Mode;

public enum ExporterMode {
    MODE_LIGHT, MODE_NORMAL, MODE_FULL;

    public String toString() {
        String[] parts = this.name().split("_");
        String part = parts[1].substring(1).toLowerCase();
        return Character.toUpperCase(parts[1].charAt(0)) + part + " " + parts[0].toLowerCase();
    }

    public Mode toProto() {
        switch (values()[ordinal()]) {
            case MODE_LIGHT:
                return Mode.MODE_LIGHT;
            case MODE_NORMAL:
                return Mode.MODE_NORMAL;
            case MODE_FULL:
                return Mode.MODE_FULL;
            default:
                throw new RuntimeException("Cannot convert unknown value");
        }
    }
}
