package com.isoplatform.api.inspection.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.junit.jupiter.api.Assertions.*;

class PhotoServiceTest {

    @Test
    void testFileCopyShouldHandleExistingFiles(@TempDir Path tempDir) throws Exception {
        // Create source file
        Path source = tempDir.resolve("source.txt");
        Files.writeString(source, "test content");

        // Create destination path
        Path destination = tempDir.resolve("destination.txt");

        // First copy - should succeed
        Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
        assertTrue(Files.exists(destination));

        // Second copy to same path - should also succeed (not throw exception)
        Files.copy(source, destination, StandardCopyOption.REPLACE_EXISTING);
        assertTrue(Files.exists(destination));
        assertEquals("test content", Files.readString(destination));
    }

    @Test
    void testFileCopyFromInputStreamWithReplaceExisting(@TempDir Path tempDir) throws Exception {
        // Simulate MultipartFile input stream scenario
        byte[] content = "photo data".getBytes();
        InputStream inputStream = new ByteArrayInputStream(content);

        Path destination = tempDir.resolve("photo.jpg");

        // First copy
        Files.copy(inputStream, destination, StandardCopyOption.REPLACE_EXISTING);
        assertTrue(Files.exists(destination));
        assertEquals("photo data", Files.readString(destination));

        // Second copy with new stream should succeed with REPLACE_EXISTING
        InputStream inputStream2 = new ByteArrayInputStream("updated photo".getBytes());
        Files.copy(inputStream2, destination, StandardCopyOption.REPLACE_EXISTING);
        assertTrue(Files.exists(destination));
        assertEquals("updated photo", Files.readString(destination));
    }

    @Test
    void testFileCopyWithoutOptionsFails(@TempDir Path tempDir) throws Exception {
        Path source = tempDir.resolve("source.txt");
        Files.writeString(source, "test");

        Path destination = tempDir.resolve("destination.txt");

        // First copy succeeds
        Files.copy(source, destination);

        // Second copy without options should throw exception
        assertThrows(FileAlreadyExistsException.class, () -> {
            Files.copy(source, destination); // Throws FileAlreadyExistsException
        });
    }

    @Test
    void testInputStreamCopyWithoutOptionsFails(@TempDir Path tempDir) throws Exception {
        // Simulate MultipartFile input stream scenario
        byte[] content = "photo data".getBytes();
        InputStream inputStream = new ByteArrayInputStream(content);

        Path destination = tempDir.resolve("photo.jpg");

        // First copy succeeds
        Files.copy(inputStream, destination);
        assertTrue(Files.exists(destination));

        // Second copy without options should throw exception
        InputStream inputStream2 = new ByteArrayInputStream("new data".getBytes());
        assertThrows(FileAlreadyExistsException.class, () -> {
            Files.copy(inputStream2, destination); // Throws FileAlreadyExistsException
        });
    }
}
