package com.quarkslab.quokka.util;

import ghidra.program.model.listing.Program;
import ghidra.program.database.mem.FileBytes;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * SHA-256 hash computation for binary files.
 * The hash must match what the Python consumer computes: sha256 of raw on-disk bytes.
 */
public final class HashUtil {

    private HashUtil() {}

    /**
     * Compute SHA-256 from Ghidra's FileBytes API (original imported file bytes).
     * Returns lowercase hex string.
     */
    public static String sha256FromFileBytes(Program program) throws IOException {
        List<FileBytes> allFileBytes = program.getMemory().getAllFileBytes();
        if (allFileBytes.isEmpty()) {
            return null;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            FileBytes fileBytes = allFileBytes.get(0);
            long size = fileBytes.getSize();
            byte[] buffer = new byte[8192];

            for (long offset = 0; offset < size; offset += buffer.length) {
                int len = (int) Math.min(buffer.length, size - offset);
                for (int i = 0; i < len; i++) {
                    buffer[i] = fileBytes.getOriginalByte(offset + i);
                }
                digest.update(buffer, 0, len);
            }

            return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Compute SHA-256 from a file on disk.
     * Returns lowercase hex string.
     */
    public static String sha256FromDisk(File file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];

            try (FileInputStream fis = new FileInputStream(file)) {
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }

            return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Compute SHA-256 hash, trying FileBytes first, then disk fallback.
     */
    public static String computeHash(Program program, File binaryFile)
            throws IOException {
        // Try FileBytes first (works even if file has been moved)
        String hash = sha256FromFileBytes(program);
        if (hash != null) {
            return hash;
        }

        // Fallback to reading from disk
        if (binaryFile != null && binaryFile.exists()) {
            return sha256FromDisk(binaryFile);
        }

        throw new IOException("Cannot compute hash: no FileBytes and binary not found");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
