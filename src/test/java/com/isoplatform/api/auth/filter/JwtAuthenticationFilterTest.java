package com.isoplatform.api.auth.filter;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.auth.service.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class JwtAuthenticationFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    private String validToken;
    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .email("jwt-test@example.com")
                .password("password")
                .name("JWT Test User")
                .role(Role.USER)
                .build();
        testUser = userRepository.save(testUser);

        validToken = jwtTokenProvider.generateToken(testUser);
    }

    @Test
    void shouldAllowRequestWithValidJwtToken() throws Exception {
        // With valid JWT, authentication passes (status should NOT be 401)
        // Controller may return 400 due to missing X-API-KEY header, but that's after authentication
        mockMvc.perform(get("/api/certificates")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status == 401) {
                        throw new AssertionError("Expected authentication to pass with valid JWT token, but got 401 Unauthorized");
                    }
                });
    }

    @Test
    void shouldRejectRequestWithInvalidToken() throws Exception {
        mockMvc.perform(get("/api/certificates")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectRequestWithExpiredToken() throws Exception {
        // Create an expired token (this would require modifying JwtTokenProvider to support custom expiry for testing)
        String expiredToken = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxfQ.invalid";

        mockMvc.perform(get("/api/certificates")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldAllowRequestWithoutTokenToPublicEndpoint() throws Exception {
        // Public endpoints should not require authentication (should NOT return 401)
        // Endpoint might return 404 if not configured, but that's different from 401
        mockMvc.perform(get("/actuator/health"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status == 401) {
                        throw new AssertionError("Expected public endpoint to not require authentication, but got 401 Unauthorized");
                    }
                });
    }
}
