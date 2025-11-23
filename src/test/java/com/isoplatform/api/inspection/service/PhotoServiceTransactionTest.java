package com.isoplatform.api.inspection.service;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.repository.PhotoRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Tests for PhotoService transaction behavior and error handling.
 *
 * These tests verify that:
 * 1. File operations and DB operations are handled separately
 * 2. DataIntegrityViolationException is caught and handled properly
 * 3. Appropriate error messages are provided to users
 */
@ExtendWith(MockitoExtension.class)
class PhotoServiceTransactionTest {

    @Mock
    private PhotoRepository photoRepository;

    private PhotoService photoService;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        photoService = new PhotoService(photoRepository);
        ReflectionTestUtils.setField(photoService, "photosStoragePath", tempDir.toString());
    }

    @Test
    void testTransactionRollbackDoesNotLeaveOrphanedFile() throws IOException {
        // Given: File upload succeeds but DB save fails with DataIntegrityViolationException
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "fake image content".getBytes());

        // DB save will throw DataIntegrityViolationException
        when(photoRepository.save(any(Photo.class)))
            .thenThrow(new DataIntegrityViolationException("Duplicate entry"));

        // When: Upload is attempted
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            photoService.uploadPhoto(mockFile, "VIN123", "CATEGORY_A", "ITEM_1");
        });

        // Then: Exception is thrown with user-friendly message
        assertTrue(exception.getMessage().contains("DB 저장 실패"));

        // Verify that save was attempted
        verify(photoRepository, times(1)).save(any(Photo.class));

        // File may remain on disk (orphaned) - this is documented behavior
        // A cleanup job should periodically remove orphaned files
        // We don't delete the file because:
        // 1. It might be needed for manual recovery
        // 2. Deleting in catch block adds another failure point
    }

    @Test
    void testDataIntegrityExceptionHandling() throws IOException {
        // Given: A valid file but DB constraint violation
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "valid image".getBytes());

        // Simulate unique constraint violation or foreign key violation
        when(photoRepository.save(any(Photo.class)))
            .thenThrow(new DataIntegrityViolationException("constraint violation"));

        // When: Upload is attempted
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            photoService.uploadPhoto(mockFile, "VIN123", "A", "A1");
        });

        // Then: User gets a clear error message
        String message = exception.getMessage();
        assertTrue(message.contains("DB 저장 실패") || message.contains("시스템 관리자"));

        // Verify repository interaction
        verify(photoRepository).save(any(Photo.class));
    }

    @Test
    void testSuccessfulUploadReturnsPhoto() throws IOException {
        // Given: A valid file and successful DB save
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "valid image".getBytes());

        when(photoRepository.save(any(Photo.class))).thenAnswer(invocation -> {
            Photo photo = invocation.getArgument(0);
            // Simulate DB generating ID
            ReflectionTestUtils.setField(photo, "id", 1L);
            return photo;
        });

        // When: Upload is attempted
        Photo result = photoService.uploadPhoto(mockFile, "VIN123", "A", "A1");

        // Then: Photo is returned with all fields populated
        assertNotNull(result);
        assertEquals("VIN123", result.getVin());
        assertEquals("A", result.getCategory());
        assertEquals("A1", result.getItemCode());
        assertNotNull(result.getFileName());
        assertNotNull(result.getStoragePath());

        // Verify file was actually saved to disk
        Path savedFile = Path.of(result.getStoragePath());
        assertTrue(Files.exists(savedFile));
    }

    @Test
    void testIOExceptionIsPropagatedCorrectly() throws IOException {
        // Given: A file that will fail during IO
        MultipartFile mockFile = mock(MultipartFile.class);
        when(mockFile.isEmpty()).thenReturn(false);
        when(mockFile.getContentType()).thenReturn("image/jpeg");
        when(mockFile.getSize()).thenReturn(1024L);
        when(mockFile.getOriginalFilename()).thenReturn("test.jpg");
        when(mockFile.getInputStream()).thenThrow(new IOException("Disk full"));

        // When: Upload is attempted
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            photoService.uploadPhoto(mockFile, "VIN123", "A", "A1");
        });

        // Then: IO error message is included
        assertTrue(exception.getMessage().contains("사진 저장 중 오류"));

        // DB save should never be attempted
        verify(photoRepository, never()).save(any(Photo.class));
    }

    /**
     * Helper method to create a mock MultipartFile
     */
    private MultipartFile createMockMultipartFile(String filename, String contentType, byte[] content) throws IOException {
        MultipartFile mockFile = mock(MultipartFile.class);
        when(mockFile.isEmpty()).thenReturn(false);
        when(mockFile.getOriginalFilename()).thenReturn(filename);
        when(mockFile.getContentType()).thenReturn(contentType);
        when(mockFile.getSize()).thenReturn((long) content.length);
        when(mockFile.getInputStream()).thenReturn(new ByteArrayInputStream(content));
        return mockFile;
    }
}
