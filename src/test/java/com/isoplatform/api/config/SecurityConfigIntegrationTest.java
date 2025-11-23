package com.isoplatform.api.config;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.auth.service.JwtTokenProvider;
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
class SecurityConfigIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private UserRepository userRepository;

    @Test
    void shouldProtectCertificateEndpointsWithJwt() throws Exception {
        // Without token - should fail with 401 Unauthorized
        mockMvc.perform(get("/api/certificates"))
                .andExpect(status().isUnauthorized());

        // With valid token - should pass authentication (may fail with 400 due to missing X-API-KEY, but not 401)
        User user = User.builder()
                .email("security-test@example.com")
                .password("password")
                .name("Security Test")
                .role(Role.USER)
                .provider("LOCAL")
                .build();
        user = userRepository.save(user);

        String token = jwtTokenProvider.generateToken(user);

        // With valid JWT, authentication passes (status should NOT be 401)
        mockMvc.perform(get("/api/certificates")
                        .header("Authorization", "Bearer " + token))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status == 401) {
                        throw new AssertionError("Expected authentication to pass with valid JWT token, but got 401 Unauthorized");
                    }
                });
    }

    @Test
    void shouldAllowPublicEndpointsWithoutAuth() throws Exception {
        // Actuator endpoints might not be configured, so we test with a more generic approach
        // The key is that it should NOT return 401 Unauthorized for this path pattern
        mockMvc.perform(get("/actuator/health"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status == 401) {
                        throw new AssertionError("Expected public endpoint to not require authentication, but got 401 Unauthorized");
                    }
                });
    }

    @Test
    void shouldAllowAuthEndpointsWithoutAuth() throws Exception {
        // Public auth endpoints should be accessible without token
        // Test login endpoint - should NOT return 401 (may return 405 for GET, but not 401)
        mockMvc.perform(get("/api/auth/login"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status == 401) {
                        throw new AssertionError("Expected public auth endpoint /api/auth/login to not require JWT authentication, but got 401 Unauthorized");
                    }
                });
    }

    @Test
    void shouldRequireAuthForLogoutAllEndpoint() throws Exception {
        // /api/auth/logout-all requires authentication - should return 401 without token
        mockMvc.perform(get("/api/auth/logout-all"))
                .andExpect(status().isUnauthorized());
    }
}
