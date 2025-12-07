package com.isoplatform.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.dto.WithdrawRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class WithdrawControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void withdraw_shouldReturnSuccessWithValidRequest() throws Exception {
        // Given: Create and authenticate user
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("withdraw-test@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Withdraw Test User");

        MvcResult signupResult = mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated())
                .andReturn();

        String signupResponse = signupResult.getResponse().getContentAsString();
        Map<String, Object> signupData = objectMapper.readValue(signupResponse, Map.class);
        String accessToken = (String) signupData.get("accessToken");

        // When: Call withdraw with correct password
        WithdrawRequest withdrawRequest = new WithdrawRequest();
        withdrawRequest.setReason("Testing withdrawal");
        withdrawRequest.setPassword("Password123!");

        // Then: Should return success
        mockMvc.perform(post("/api/auth/withdraw")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(withdrawRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void withdraw_shouldReturnUnauthorizedWithoutToken() throws Exception {
        // Given: Withdraw request without authentication
        WithdrawRequest withdrawRequest = new WithdrawRequest();
        withdrawRequest.setReason("Testing withdrawal");
        withdrawRequest.setPassword("Password123!");

        // When/Then: Should return unauthorized
        mockMvc.perform(post("/api/auth/withdraw")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(withdrawRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void withdraw_shouldReturnBadRequestWithWrongPassword() throws Exception {
        // Given: Create and authenticate user
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("wrong-password-withdraw@example.com");
        signupRequest.setPassword("CorrectPassword123!");
        signupRequest.setName("Wrong Password Test");

        MvcResult signupResult = mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andExpect(status().isCreated())
                .andReturn();

        String signupResponse = signupResult.getResponse().getContentAsString();
        Map<String, Object> signupData = objectMapper.readValue(signupResponse, Map.class);
        String accessToken = (String) signupData.get("accessToken");

        // When: Call withdraw with wrong password
        WithdrawRequest withdrawRequest = new WithdrawRequest();
        withdrawRequest.setReason("Testing withdrawal");
        withdrawRequest.setPassword("WrongPassword123!");

        // Then: Should return 401 with INVALID_CREDENTIALS error
        mockMvc.perform(post("/api/auth/withdraw")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(withdrawRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }
}
