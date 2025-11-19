package com.isoplatform.api.certification;

import com.isoplatform.api.certification.controller.CertificateController;
import com.isoplatform.api.certification.service.CertificateService;
import com.isoplatform.api.inspection.VehicleChecklist;
import com.isoplatform.api.inspection.service.ChecklistService;
import com.isoplatform.api.security.ApiKeyService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CertificateFromChecklistTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ApiKeyService apiKeyService;

    @BeforeEach
    void setUp() {
        when(apiKeyService.validateApiKeyWithDetails(anyString()))
                .thenReturn(new ApiKeyService.ApiKeyValidationResult(true, "Valid"));
    }

    @Test
    void createCertificateFromChecklist_shouldReturn200_whenChecklistExists() throws Exception {
        mockMvc.perform(post("/api/certificates/from-checklist")
                        .param("checklistId", "1")
                        .header("X-API-KEY", "test-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.certNumber").exists())
                .andExpect(jsonPath("$.vin").exists());
    }

    @Test
    void createCertificateFromChecklist_shouldReturn400_whenChecklistNotFound() throws Exception {
        mockMvc.perform(post("/api/certificates/from-checklist")
                        .param("checklistId", "999999")
                        .header("X-API-KEY", "test-key"))
                .andExpect(status().isBadRequest());
    }
}
