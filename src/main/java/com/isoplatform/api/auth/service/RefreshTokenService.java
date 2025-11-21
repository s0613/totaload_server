package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration-time:604800000}") // 7 days in milliseconds
    private Long refreshExpirationMs;

    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Revoke all existing tokens for this user (single device policy)
        revokeAllUserTokens(user);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(generateRefreshToken())
                .expiryDate(LocalDateTime.now().plusSeconds(refreshExpirationMs / 1000))
                .build();

        refreshToken = refreshTokenRepository.save(refreshToken);
        log.info("Created refresh token for user: {}", user.getEmail());

        return refreshToken;
    }

    @Transactional
    public RefreshToken verifyRefreshToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        if (refreshToken.isRevoked()) {
            throw new RuntimeException("Refresh token has been revoked");
        }

        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException("Refresh token has expired");
        }

        // Update last used timestamp
        refreshToken.setLastUsedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);

        return refreshToken;
    }

    @Transactional
    public void revokeToken(String token) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
        log.info("Revoked refresh token for user: {}", refreshToken.getUser().getEmail());
    }

    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllByUser(user);
        log.info("Revoked all refresh tokens for user: {}", user.getEmail());
    }

    @Transactional
    public int deleteExpiredTokens() {
        int deleted = refreshTokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
        log.info("Deleted {} expired refresh tokens", deleted);
        return deleted;
    }

    private String generateRefreshToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }
}
