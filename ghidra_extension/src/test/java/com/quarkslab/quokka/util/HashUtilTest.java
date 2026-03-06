package com.quarkslab.quokka.util;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class HashUtilTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void testSha256FromDisk() throws Exception {
        // "hello" -> known SHA-256
        File testFile = tempFolder.newFile("test.bin");
        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write("hello".getBytes(StandardCharsets.UTF_8));
        }

        String hash = HashUtil.sha256FromDisk(testFile);
        assertNotNull(hash);
        // SHA-256 of "hello" = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                hash);
    }

    @Test
    public void testSha256EmptyFile() throws Exception {
        File testFile = tempFolder.newFile("empty.bin");
        String hash = HashUtil.sha256FromDisk(testFile);
        assertNotNull(hash);
        // SHA-256 of empty string = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                hash);
    }

    @Test
    public void testHashIsLowercaseHex() throws Exception {
        File testFile = tempFolder.newFile("test2.bin");
        try (FileOutputStream fos = new FileOutputStream(testFile)) {
            fos.write(new byte[]{0x00, (byte) 0xFF, 0x42});
        }

        String hash = HashUtil.sha256FromDisk(testFile);
        assertNotNull(hash);
        assertEquals(64, hash.length());
        // Verify all lowercase hex
        assertEquals(hash, hash.toLowerCase());
        for (char c : hash.toCharArray()) {
            assert (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') :
                    "Non-hex character: " + c;
        }
    }
}
