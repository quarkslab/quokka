package com.quarkslab.quokka.compat;

import ghidra.framework.Application;

/**
 * Ghidra version detection and compatibility checks.
 * All version-specific quirks should be isolated here.
 */
public final class Compat {

    private Compat() {}

    /**
     * Get the current Ghidra application version string (e.g., "12.0.3").
     */
    public static String getGhidraVersion() {
        return Application.getApplicationVersion();
    }

    /**
     * Verify that the running Ghidra version meets the minimum requirement.
     * @throws IllegalStateException if the version is too old
     */
    public static void requireMinimumVersion(String minVersion) {
        String current = getGhidraVersion();
        if (compareVersions(current, minVersion) < 0) {
            throw new IllegalStateException(
                    "Ghidra version " + current + " is too old. "
                    + "Minimum required: " + minVersion);
        }
    }

    /**
     * Compare two version strings (e.g., "12.0.3" vs "12.0").
     * Returns negative if a < b, 0 if equal, positive if a > b.
     */
    static int compareVersions(String a, String b) {
        String[] partsA = a.split("\\.");
        String[] partsB = b.split("\\.");
        int len = Math.max(partsA.length, partsB.length);
        for (int i = 0; i < len; i++) {
            int va = i < partsA.length ? Integer.parseInt(partsA[i]) : 0;
            int vb = i < partsB.length ? Integer.parseInt(partsB[i]) : 0;
            if (va != vb) {
                return Integer.compare(va, vb);
            }
        }
        return 0;
    }
}
