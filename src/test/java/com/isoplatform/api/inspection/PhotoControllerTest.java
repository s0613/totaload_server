package com.isoplatform.api.inspection;

import com.isoplatform.api.storage.S3Service;
import com.isoplatform.api.util.S3UploadResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PhotoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private S3Service s3Service;

    @BeforeEach
    void setUp() throws Exception {
        // Mock S3Service to return upload result
        when(s3Service.uploadFile(any(org.springframework.web.multipart.MultipartFile.class), anyString(), anyString()))
                .thenReturn(S3UploadResult.builder()
                        .s3Key("photos/test-file.jpg")
                        .cloudFrontUrl("https://test.cloudfront.net/photos/test-file.jpg")
                        .build());
    }

    @Test
    @WithMockUser
    void uploadPhoto_shouldReturn200_whenValidImage() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "test-photo.jpg",
                MediaType.IMAGE_JPEG_VALUE,
                "test image content".getBytes()
        );

        // When & Then
        mockMvc.perform(multipart("/api/photos/upload")
                        .file(file)
                        .param("vin", "TEST12345VIN67890")
                        .param("category", "A")
                        .param("itemCode", "A1")
                        .header("X-API-KEY", "test-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.fileName").exists())
                .andExpect(jsonPath("$.storagePath").exists());
    }

    @Test
    @WithMockUser
    void uploadPhoto_shouldReturn400_whenFileEmpty() throws Exception {
        MockMultipartFile emptyFile = new MockMultipartFile(
                "file",
                "empty.jpg",
                MediaType.IMAGE_JPEG_VALUE,
                new byte[0]
        );

        // When & Then
        mockMvc.perform(multipart("/api/photos/upload")
                        .file(emptyFile)
                        .param("vin", "TEST12345VIN67890")
                        .param("category", "A")
                        .param("itemCode", "A1")
                        .header("X-API-KEY", "test-key"))
                .andExpect(status().isBadRequest());
    }
}
