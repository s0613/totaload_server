package com.isoplatform.api.certification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.controller.CertificateController;
import com.isoplatform.api.certification.service.CertificateService;
import com.isoplatform.api.inspection.VehicleChecklist;
import com.isoplatform.api.inspection.request.ChecklistSubmissionRequest;
import com.isoplatform.api.inspection.service.ChecklistService;
import com.isoplatform.api.storage.S3Service;
import com.isoplatform.api.util.PDFParser;
import com.isoplatform.api.util.S3UploadResult;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class CertificateFromChecklistTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EntityManager entityManager;

    @MockBean
    private PDFParser pdfParser;

    @MockBean
    private S3Service s3Service;

    @TempDir
    Path tempDir;

    private Long createdChecklistId;
    private File testPdfFile;
    private User testUser;

    @BeforeEach
    void setUp() throws Exception {
        // Use unique emails to avoid constraint violations
        String uniqueId = java.util.UUID.randomUUID().toString().substring(0, 8);

        // Create api-key-user if not exists (required for API key authentication)
        if (!userRepository.existsByEmail("api-key-user")) {
            User apiKeyUser = User.builder()
                    .email("api-key-user")
                    .password("password")
                    .name("API Key User")
                    .role(Role.USER)
                    .build();
            userRepository.save(apiKeyUser);
        }

        // Create test user
        testUser = User.builder()
                .email("test-" + uniqueId + "@example.com")
                .password("password")
                .name("테스트 사용자")
                .role(Role.USER)
                .build();
        testUser = userRepository.save(testUser);
        entityManager.flush();

        // Set up SecurityContext with the actual test user email
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        testUser.getEmail(),
                        "password",
                        Collections.emptyList()
                );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Create test PDF file for mocking
        testPdfFile = tempDir.resolve("test-certificate.pdf").toFile();
        Files.write(testPdfFile.toPath(), "Test PDF Content".getBytes());

        // Mock PDFParser to return test file path
        when(pdfParser.createCertificatePdf(any()))
                .thenReturn(testPdfFile.getAbsolutePath());

        // Mock S3Service to return upload result
        when(s3Service.uploadFile(any(File.class), anyString(), anyString(), anyString()))
                .thenReturn(S3UploadResult.builder()
                        .s3Key("certificates/test-file.pdf")
                        .cloudFrontUrl("https://test.cloudfront.net/certificates/test-file.pdf")
                        .build());

        // Create a test checklist first
        ChecklistSubmissionRequest.ChecklistItemData item1 = new ChecklistSubmissionRequest.ChecklistItemData();
        item1.setCode("A1");
        item1.setCategory("A");
        item1.setItem("스크래치");
        item1.setMaxScore(10);
        item1.setScore(8);
        item1.setRemarks("테스트");

        Map<String, Object> vehicleInfo = new HashMap<>();
        vehicleInfo.put("manufacturer", "현대자동차");
        vehicleInfo.put("model", "아반떼");
        vehicleInfo.put("year", 2020);

        ChecklistSubmissionRequest request = new ChecklistSubmissionRequest();
        request.setVehicleNumber("12가3456");
        request.setVin("TEST_VIN_FOR_CERT");
        request.setVehicleInfo(vehicleInfo);
        request.setItems(List.of(item1));
        request.setStatus("completed");

        MvcResult result = mockMvc.perform(post("/api/checklists/submit")
                        .header("X-API-KEY", "test-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        Map<String, Object> responseMap = objectMapper.readValue(responseJson, Map.class);
        createdChecklistId = Long.valueOf(responseMap.get("id").toString());
    }

    @Test
    void createCertificateFromChecklist_shouldReturn200_whenChecklistExists() throws Exception {
        // First call - creates certificate
        MvcResult result1 = mockMvc.perform(post("/api/certificates/from-checklist")
                        .param("checklistId", createdChecklistId.toString())
                        .header("X-API-KEY", "test-key"))
                .andReturn();

        // Check status - should be 200 for successful creation or 500 if there's an error
        int status = result1.getResponse().getStatus();
        String body = result1.getResponse().getContentAsString();

        // If status is 500, this is the actual test failure
        if (status == 500) {
            throw new AssertionError("Certificate creation failed with 500: " + body);
        }

        mockMvc.perform(post("/api/certificates/from-checklist")
                        .param("checklistId", createdChecklistId.toString())
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
