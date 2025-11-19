package com.isoplatform.api.inspection;

import com.isoplatform.api.security.ApiKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class PhotoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ApiKeyService apiKeyService;

    @Test
    void uploadPhoto_shouldReturn200_whenValidImage() throws Exception {
        // Given
        when(apiKeyService.validateApiKeyWithDetails(anyString()))
                .thenReturn(new ApiKeyService.ApiKeyValidationResult(true, "Valid"));

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
    void uploadPhoto_shouldReturn400_whenFileEmpty() throws Exception {
        // Given
        when(apiKeyService.validateApiKeyWithDetails(anyString()))
                .thenReturn(new ApiKeyService.ApiKeyValidationResult(true, "Valid"));

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
