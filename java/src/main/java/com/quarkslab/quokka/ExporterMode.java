package com.quarkslab.quokka;

public enum ExporterMode {
    MODE_LIGHT, MODE_NORMAL, MODE_FULL;

    public String toString() {
        String[] parts = this.name().split("_");
        String part = parts[1].substring(1).toLowerCase();
        return Character.toUpperCase(parts[1].charAt(0)) + part + " " + parts[0].toLowerCase();
    }
}
