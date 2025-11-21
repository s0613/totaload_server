package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import com.isoplatform.api.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
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
class RefreshTokenServiceTest {

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = User.builder()
                .email("refresh-test@example.com")
                .password("password")
                .name("Refresh Test User")
                .role(Role.USER)
                .build();
        testUser = userRepository.save(testUser);
    }

    @Test
    void shouldCreateRefreshToken() {
        // When
        RefreshToken token = refreshTokenService.createRefreshToken(testUser);

        // Then
        assertNotNull(token);
        assertNotNull(token.getToken());
        assertNotNull(token.getExpiryDate());
        assertEquals(testUser.getId(), token.getUser().getId());
        assertFalse(token.isRevoked());
    }

    @Test
    void shouldVerifyValidToken() {
        // Given
        RefreshToken token = refreshTokenService.createRefreshToken(testUser);

        // When
        RefreshToken verified = refreshTokenService.verifyRefreshToken(token.getToken());

        // Then
        assertNotNull(verified);
        assertEquals(token.getToken(), verified.getToken());
    }

    @Test
    void shouldThrowExceptionForExpiredToken() {
        // Given
        RefreshToken expiredToken = RefreshToken.builder()
                .user(testUser)
                .token("expired-token-123")
                .expiryDate(LocalDateTime.now().minusDays(1))
                .build();
        refreshTokenRepository.save(expiredToken);

        // When & Then
        assertThrows(RuntimeException.class, () ->
            refreshTokenService.verifyRefreshToken("expired-token-123"));
    }

    @Test
    void shouldThrowExceptionForRevokedToken() {
        // Given
        RefreshToken revokedToken = RefreshToken.builder()
                .user(testUser)
                .token("revoked-token-123")
                .expiryDate(LocalDateTime.now().plusDays(7))
                .revoked(true)
                .build();
        refreshTokenRepository.save(revokedToken);

        // When & Then
        assertThrows(RuntimeException.class, () ->
            refreshTokenService.verifyRefreshToken("revoked-token-123"));
    }

    @Test
    void shouldRevokeAllTokensForUser() {
        // Given
        RefreshToken token1 = refreshTokenService.createRefreshToken(testUser);
        RefreshToken token2 = refreshTokenService.createRefreshToken(testUser);

        // When
        refreshTokenService.revokeAllUserTokens(testUser);

        // Then
        RefreshToken refreshed1 = refreshTokenRepository.findByToken(token1.getToken()).orElse(null);
        RefreshToken refreshed2 = refreshTokenRepository.findByToken(token2.getToken()).orElse(null);

        assertNotNull(refreshed1);
        assertNotNull(refreshed2);
        assertTrue(refreshed1.isRevoked());
        assertTrue(refreshed2.isRevoked());
    }

    @Test
    void shouldDeleteExpiredTokens() {
        // Given
        RefreshToken expiredToken = RefreshToken.builder()
                .user(testUser)
                .token("to-be-deleted")
                .expiryDate(LocalDateTime.now().minusDays(1))
                .build();
        refreshTokenRepository.save(expiredToken);

        // When
        int deleted = refreshTokenService.deleteExpiredTokens();

        // Then
        assertTrue(deleted > 0);
        assertFalse(refreshTokenRepository.findByToken("to-be-deleted").isPresent());
    }
}
