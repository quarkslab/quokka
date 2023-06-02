package com.quarkslab.quokka;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Singleton responsible for building and interacting with the string_table message. It guarantees
 * that the first element (index = 0) is always the empty string and that the same string won't
 * appear twice with different indexes in the table.
 */
public class StringTableManager {
    private static StringTableManager instance; // Singleton instance

    private List<String> table = new ArrayList<>();
    private Map<String, Integer> tableIndex = new HashMap<>(); // To avoid duplicates

    private StringTableManager() {
        // First one is always the empty string to be used by unnamed data objects
        // (aka name_index = 0)
        this.table.add("");
        this.tableIndex.put("", 0);
    }

    public static StringTableManager getInstance() {
        if (StringTableManager.instance == null)
            StringTableManager.instance = new StringTableManager();
        return StringTableManager.instance;
    }

    /**
     * Add a string to the string table and return its index in the table. If the string was already
     * present don't add it and just return the index.
     * 
     * If the string is null, it is treated as an empty string
     * 
     * @param value The string to be added
     * @return The index in the string_table
     */
    public int add(String value) {
        if (value == null || value.length() == 0)
            return 0;

        if (this.tableIndex.containsKey(value))
            return this.tableIndex.get(value);

        int pos = this.table.size();
        this.tableIndex.put(value, pos);
        this.table.add(value);
        return pos;
    }

    public List<String> getAll() {
        return this.table;
    }
}
