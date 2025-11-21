package com.isoplatform.api.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.LoginRequest;
import com.isoplatform.api.auth.dto.RefreshTokenRequest;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.repository.UserRepository;
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
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Test
    void signup_shouldReturn201WithTokens() throws Exception {
        SignupRequest request = new SignupRequest();
        request.setEmail("controller-test@example.com");
        request.setPassword("Password123!");
        request.setName("Controller Test User");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.email").value("controller-test@example.com"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void signup_shouldReturn409WhenEmailExists() throws Exception {
        // First signup
        SignupRequest request1 = new SignupRequest();
        request1.setEmail("duplicate@example.com");
        request1.setPassword("Password123!");
        request1.setName("User 1");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request1)));

        // Try to signup again with same email
        SignupRequest request2 = new SignupRequest();
        request2.setEmail("duplicate@example.com");
        request2.setPassword("DifferentPass123!");
        request2.setName("User 2");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request2)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("EMAIL_EXISTS"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void signup_shouldReturn400WhenInvalidData() throws Exception {
        SignupRequest request = new SignupRequest();
        request.setEmail("invalid-email");
        request.setPassword("Password123!");
        request.setName("Test User");

        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_shouldReturn200WithTokens() throws Exception {
        // First, register a user
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("login-test@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Login Test");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)));

        // Then, login
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("login-test@example.com");
        loginRequest.setPassword("Password123!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.email").value("login-test@example.com"));
    }

    @Test
    void login_shouldReturn401WhenInvalidCredentials() throws Exception {
        // First, register a user
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("wrong-pass@example.com");
        signupRequest.setPassword("CorrectPassword123!");
        signupRequest.setName("Wrong Pass Test");

        mockMvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signupRequest)));

        // Then, try to login with wrong password
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("wrong-pass@example.com");
        loginRequest.setPassword("WrongPassword!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void login_shouldReturn400WhenOAuth2User() throws Exception {
        // Create OAuth2 user
        User oauth2User = User.builder()
                .email("oauth2@example.com")
                .name("OAuth2 User")
                .provider("GOOGLE")
                .role(Role.USER)
                .password("") // OAuth2 users don't have passwords
                .build();
        userRepository.save(oauth2User);

        // Attempt local login
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("oauth2@example.com");
        loginRequest.setPassword("Password123!");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("OAUTH2_USER"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void refresh_shouldReturn200WithNewTokens() throws Exception {
        // First, register and get tokens
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("refresh-test@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Refresh Test");

        MvcResult signupResult = mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andReturn();

        String signupResponse = signupResult.getResponse().getContentAsString();
        Map<String, Object> signupData = objectMapper.readValue(signupResponse, Map.class);
        String refreshToken = (String) signupData.get("refreshToken");

        // Then, refresh the token
        RefreshTokenRequest refreshRequest = new RefreshTokenRequest();
        refreshRequest.setRefreshToken(refreshToken);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.email").value("refresh-test@example.com"));
    }

    @Test
    void refresh_shouldReturn401WhenInvalidToken() throws Exception {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("invalid-token");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_TOKEN"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void logout_shouldReturn200() throws Exception {
        // First, register and get tokens
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("logout-test@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Logout Test");

        MvcResult signupResult = mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signupRequest)))
                .andReturn();

        String signupResponse = signupResult.getResponse().getContentAsString();
        Map<String, Object> signupData = objectMapper.readValue(signupResponse, Map.class);
        String refreshToken = (String) signupData.get("refreshToken");

        // Then, logout
        RefreshTokenRequest logoutRequest = new RefreshTokenRequest();
        logoutRequest.setRefreshToken(refreshToken);

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isOk());

        // Verify token is revoked by trying to refresh
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutRequest)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_TOKEN"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    void logout_shouldReturn401WhenInvalidToken() throws Exception {
        RefreshTokenRequest request = new RefreshTokenRequest();
        request.setRefreshToken("invalid-token-for-logout");

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_TOKEN"))
                .andExpect(jsonPath("$.message").exists())
                .andExpect(jsonPath("$.timestamp").exists());
    }
}
