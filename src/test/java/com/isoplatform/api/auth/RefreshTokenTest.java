package com.isoplatform.api.auth;

import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import com.isoplatform.api.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class RefreshTokenTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    void shouldCreateAndSaveRefreshToken() {
        // Given
        User user = User.builder()
                .email("test@example.com")
                .password("password")
                .name("Test User")
                .role(Role.USER)
                .build();
        user = userRepository.save(user);

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token("test-refresh-token")
                .expiryDate(LocalDateTime.now().plusDays(7))
                .build();

        // When
        RefreshToken saved = refreshTokenRepository.save(token);

        // Then
        assertNotNull(saved.getId());
        assertEquals("test-refresh-token", saved.getToken());
        assertNotNull(saved.getCreatedAt());
        assertFalse(saved.isRevoked());
    }

    @Test
    void shouldFindByToken() {
        // Given
        User user = User.builder()
                .email("test2@example.com")
                .password("password")
                .name("Test User 2")
                .role(Role.USER)
                .build();
        user = userRepository.save(user);

        RefreshToken token = RefreshToken.builder()
                .user(user)
                .token("find-me-token")
                .expiryDate(LocalDateTime.now().plusDays(7))
                .build();
        refreshTokenRepository.save(token);

        // When
        RefreshToken found = refreshTokenRepository.findByToken("find-me-token")
                .orElse(null);

        // Then
        assertNotNull(found);
        assertEquals("find-me-token", found.getToken());
    }

    @Test
    void shouldDeleteExpiredTokens() {
        // Given
        User user = User.builder()
                .email("test3@example.com")
                .password("password")
                .name("Test User 3")
                .role(Role.USER)
                .build();
        user = userRepository.save(user);

        RefreshToken expiredToken = RefreshToken.builder()
                .user(user)
                .token("expired-token")
                .expiryDate(LocalDateTime.now().minusDays(1))
                .build();
        refreshTokenRepository.save(expiredToken);

        // When
        int deleted = refreshTokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());

        // Then
        assertTrue(deleted > 0);
    }
}
