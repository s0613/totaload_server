package com.isoplatform.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.dto.AppleSignInRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AppleSignInControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void appleSignIn_shouldReturnUnauthorizedForInvalidToken() throws Exception {
        AppleSignInRequest request = new AppleSignInRequest();
        request.setIdentityToken("invalid.jwt.token");

        mockMvc.perform(post("/api/auth/mobile/apple")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void appleSignIn_shouldReturnBadRequestWithoutToken() throws Exception {
        AppleSignInRequest request = new AppleSignInRequest();
        // identityToken 없음

        mockMvc.perform(post("/api/auth/mobile/apple")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
