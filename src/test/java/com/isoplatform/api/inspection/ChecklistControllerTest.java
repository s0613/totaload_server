package com.isoplatform.api.inspection;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.inspection.request.ChecklistSubmissionRequest;
import com.isoplatform.api.security.ApiKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ChecklistControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private ApiKeyService apiKeyService;

    @Test
    void submitChecklist_shouldReturn200_whenValidData() throws Exception {
        // Given
        when(apiKeyService.validateApiKeyWithDetails(anyString()))
                .thenReturn(new ApiKeyService.ApiKeyValidationResult(true, "Valid"));

        ChecklistSubmissionRequest.ChecklistItemData item1 = new ChecklistSubmissionRequest.ChecklistItemData();
        item1.setCode("A1");
        item1.setCategory("A");
        item1.setItem("스크래치(길이·부위별)");
        item1.setMaxScore(10);
        item1.setScore(8);
        item1.setRemarks("약간의 스크래치 있음");

        Map<String, Object> vehicleInfo = new HashMap<>();
        vehicleInfo.put("manufacturer", "현대자동차");
        vehicleInfo.put("modelName", "아반떼");
        vehicleInfo.put("year", 2020);

        ChecklistSubmissionRequest request = new ChecklistSubmissionRequest();
        request.setVehicleNumber("12가3456");
        request.setVin("TEST12345VIN67890");
        request.setVehicleInfo(vehicleInfo);
        request.setItems(List.of(item1));
        request.setStatus("completed");

        // When & Then
        mockMvc.perform(post("/api/checklists/submit")
                        .header("X-API-KEY", "test-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").exists())
                .andExpect(jsonPath("$.vin").value("TEST12345VIN67890"))
                .andExpect(jsonPath("$.totalScore").exists())
                .andExpect(jsonPath("$.maxTotalScore").exists());
    }

    @Test
    void submitChecklist_shouldReturn400_whenVinMissing() throws Exception {
        // Given
        when(apiKeyService.validateApiKeyWithDetails(anyString()))
                .thenReturn(new ApiKeyService.ApiKeyValidationResult(true, "Valid"));

        ChecklistSubmissionRequest request = new ChecklistSubmissionRequest();
        request.setVehicleNumber("12가3456");
        // Missing VIN

        // When & Then
        mockMvc.perform(post("/api/checklists/submit")
                        .header("X-API-KEY", "test-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
