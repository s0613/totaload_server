package com.isoplatform.api.inspection.service;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.repository.PhotoRepository;
import com.isoplatform.api.storage.S3Service;
import com.isoplatform.api.util.S3UploadResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Tests for PhotoService transaction behavior and error handling with S3 storage.
 *
 * These tests verify that:
 * 1. S3 upload and DB operations are handled separately
 * 2. DataIntegrityViolationException triggers S3 cleanup
 * 3. Appropriate error messages are provided to users
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PhotoServiceTransactionTest {

    @Mock
    private PhotoRepository photoRepository;

    @Mock
    private S3Service s3Service;

    private PhotoService photoService;

    @BeforeEach
    void setUp() {
        photoService = new PhotoService(photoRepository, s3Service);
    }

    @Test
    void testTransactionRollbackTriggersS3Cleanup() throws IOException {
        // Given: S3 upload succeeds but DB save fails
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "fake image content".getBytes());

        S3UploadResult uploadResult = new S3UploadResult("photos/test-key.jpg", "https://cdn.example.com/photos/test-key.jpg");
        when(s3Service.uploadFile(any(MultipartFile.class), anyString(), anyString()))
            .thenReturn(uploadResult);

        when(photoRepository.save(any(Photo.class)))
            .thenThrow(new DataIntegrityViolationException("Duplicate entry"));

        // When: Upload is attempted
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            photoService.uploadPhoto(mockFile, "VIN123", "A", "A1");
        });

        // Then: Exception is thrown with user-friendly message
        assertTrue(exception.getMessage().contains("DB 저장 실패"));

        // Verify S3 cleanup was attempted
        verify(s3Service).deleteFile("photos/test-key.jpg");
    }

    @Test
    void testDataIntegrityExceptionHandling() throws IOException {
        // Given: A valid file but DB constraint violation
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "valid image".getBytes());

        S3UploadResult uploadResult = new S3UploadResult("photos/test-key.jpg", "https://cdn.example.com/photos/test-key.jpg");
        when(s3Service.uploadFile(any(MultipartFile.class), anyString(), anyString()))
            .thenReturn(uploadResult);

        when(photoRepository.save(any(Photo.class)))
            .thenThrow(new DataIntegrityViolationException("constraint violation"));

        // When: Upload is attempted
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            photoService.uploadPhoto(mockFile, "VIN123", "A", "A1");
        });

        // Then: User gets a clear error message
        String message = exception.getMessage();
        assertTrue(message.contains("DB 저장 실패"));

        // Verify repository interaction
        verify(photoRepository).save(any(Photo.class));
    }

    @Test
    void testSuccessfulUploadReturnsPhoto() throws IOException {
        // Given: A valid file and successful S3 upload and DB save
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "valid image".getBytes());

        S3UploadResult uploadResult = new S3UploadResult("photos/VIN123_A_A1_uuid.jpg", "https://cdn.example.com/photos/VIN123_A_A1_uuid.jpg");
        when(s3Service.uploadFile(any(MultipartFile.class), anyString(), anyString()))
            .thenReturn(uploadResult);

        when(photoRepository.save(any(Photo.class))).thenAnswer(invocation -> {
            Photo photo = invocation.getArgument(0);
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
        assertEquals("photos/VIN123_A_A1_uuid.jpg", result.getStoragePath());
        assertEquals("https://cdn.example.com/photos/VIN123_A_A1_uuid.jpg", result.getCloudFrontUrl());
    }

    @Test
    void testS3UploadFailureThrowsException() throws IOException {
        // Given: A file that will fail during S3 upload
        MultipartFile mockFile = createMockMultipartFile("test.jpg", "image/jpeg", "valid image".getBytes());

        when(s3Service.uploadFile(any(MultipartFile.class), anyString(), anyString()))
            .thenThrow(new IOException("S3 upload failed"));

        // When: Upload is attempted
        RuntimeException exception = assertThrows(RuntimeException.class, () -> {
            photoService.uploadPhoto(mockFile, "VIN123", "A", "A1");
        });

        // Then: S3 error message is included
        assertTrue(exception.getMessage().contains("사진 업로드 중 오류"));

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
