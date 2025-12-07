package com.isoplatform.api.inspection.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;

import com.isoplatform.api.inspection.repository.PhotoRepository;
import com.isoplatform.api.storage.S3Service;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PhotoService input validation.
 *
 * <p>
 * Verifies that only safe image formats are allowed:
 * - Allowed: JPEG, PNG, WebP, GIF
 * - Rejected: SVG (XSS risk), BMP, and non-image types
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class PhotoServiceValidationTest {

    @Mock
    private PhotoRepository photoRepository;

    @Mock
    private S3Service s3Service;

    private PhotoService photoService;

    @BeforeEach
    void setUp() {
        photoService = new PhotoService(photoRepository, s3Service);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif"
    })
    void testAllowedImageFormatsPass(String contentType) {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "test.jpg",
            contentType,
            "fake image content".getBytes()
        );

        // Should NOT throw exception - invoking validateFile via reflection
        // since it's a private method, we test it through uploadPhoto behavior
        // For direct testing, we use ReflectionTestUtils
        assertDoesNotThrow(() -> {
            ReflectionTestUtils.invokeMethod(photoService, "validateFile", file);
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "image/svg+xml",
        "image/bmp",
        "application/json",
        "text/plain"
    })
    void testDisallowedFormatsThrowException(String contentType) {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "test.jpg",
            contentType,
            "fake content".getBytes()
        );

        // Should throw IllegalArgumentException for disallowed formats
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> ReflectionTestUtils.invokeMethod(photoService, "validateFile", file)
        );

        // Verify error message mentions allowed formats
        assertTrue(exception.getMessage().contains("JPEG") ||
                   exception.getMessage().contains("PNG") ||
                   exception.getMessage().contains("WebP") ||
                   exception.getMessage().contains("GIF") ||
                   exception.getMessage().contains("지원하는 이미지 형식"));
    }

    @Test
    void testFileSizeValidation() {
        // Create file larger than 10MB limit
        byte[] largeContent = new byte[11 * 1024 * 1024]; // 11MB
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "large-test.jpg",
            "image/jpeg",
            largeContent
        );

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> ReflectionTestUtils.invokeMethod(photoService, "validateFile", file)
        );

        assertTrue(exception.getMessage().contains("10MB") ||
                   exception.getMessage().contains("초과"));
    }

    @Test
    void testEmptyFileValidation() {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "empty.jpg",
            "image/jpeg",
            new byte[0]
        );

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> ReflectionTestUtils.invokeMethod(photoService, "validateFile", file)
        );

        assertTrue(exception.getMessage().contains("비어있습니다"));
    }

    @Test
    void testNullContentTypeValidation() {
        MockMultipartFile file = new MockMultipartFile(
            "file",
            "test.jpg",
            null,
            "content".getBytes()
        );

        assertThrows(
            IllegalArgumentException.class,
            () -> ReflectionTestUtils.invokeMethod(photoService, "validateFile", file)
        );
    }
}
