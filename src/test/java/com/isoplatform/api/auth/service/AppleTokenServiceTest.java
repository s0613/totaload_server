package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class AppleTokenServiceTest {

    @Autowired
    private AppleTokenService appleTokenService;

    @Test
    void verifyIdToken_shouldThrowExceptionForInvalidToken() {
        // Given
        String invalidToken = "invalid.jwt.token";

        // When & Then
        assertThrows(InvalidCredentialsException.class,
                () -> appleTokenService.verifyIdToken(invalidToken));
    }

    @Test
    void verifyIdToken_shouldThrowExceptionForExpiredToken() {
        // Given - 만료된 토큰 (실제 Apple 토큰 포맷이지만 만료됨)
        String expiredToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiY29tLnRvdGFsb2FkLmFwcCIsImV4cCI6MTYwMDAwMDAwMCwiaWF0IjoxNjAwMDAwMDAwLCJzdWIiOiIwMDEyMzQuc29tZXVzZXJpZC5hYmNkIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZW1haWxfdmVyaWZpZWQiOiJ0cnVlIn0.fake_signature";

        // When & Then
        assertThrows(InvalidCredentialsException.class,
                () -> appleTokenService.verifyIdToken(expiredToken));
    }
}
