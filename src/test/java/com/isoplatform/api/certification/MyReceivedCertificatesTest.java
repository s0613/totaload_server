package com.isoplatform.api.certification;

import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.repository.CertificateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class MyReceivedCertificatesTest {

    private static final String TEST_EMAIL = "test@example.com";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        // Create test user if not exists (required for getCurrentUser() in service)
        if (userRepository.findByEmail(TEST_EMAIL).isEmpty()) {
            User testUser = User.builder()
                    .email(TEST_EMAIL)
                    .name("Test User")
                    .password("encoded_password")
                    .build();
            userRepository.save(testUser);
        }
    }

    @Test
    @WithMockUser(username = TEST_EMAIL)
    void getMyReceivedCertificates_shouldReturnUserCertificates() throws Exception {
        mockMvc.perform(get("/api/certificates/my-received"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void getMyReceivedCertificates_withoutAuth_shouldReturn401() throws Exception {
        mockMvc.perform(get("/api/certificates/my-received"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = TEST_EMAIL)
    void getMyReceivedCertificates_withNoCertificates_shouldReturnEmptyList() throws Exception {
        // 테스트 사용자에게 인증서가 없는 상태에서 빈 배열 반환 확인
        mockMvc.perform(get("/api/certificates/my-received"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));
    }
}
