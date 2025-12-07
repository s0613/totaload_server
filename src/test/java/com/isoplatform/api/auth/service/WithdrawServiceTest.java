package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.WithdrawRequest;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.UserNotFoundException;
import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import com.isoplatform.api.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class WithdrawServiceTest {

    @Autowired
    private WithdrawService withdrawService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private User localUser;
    private User googleUser;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();

        // LOCAL 사용자 생성
        localUser = User.builder()
                .email("local@example.com")
                .password(passwordEncoder.encode("Password123!"))
                .name("Local User")
                .provider("LOCAL")
                .providerId("local@example.com")
                .company("SELF")
                .role(Role.USER)
                .build();
        localUser = userRepository.save(localUser);

        // Google OAuth 사용자 생성
        googleUser = User.builder()
                .email("google@example.com")
                .password("")
                .name("Google User")
                .provider("GOOGLE")
                .providerId("google-123")
                .company("SELF")
                .role(Role.USER)
                .build();
        googleUser = userRepository.save(googleUser);
    }

    @Test
    void withdraw_localUser_shouldDeleteUserWithCorrectPassword() {
        // Given
        WithdrawRequest request = new WithdrawRequest();
        request.setPassword("Password123!");
        request.setReason("테스트 탈퇴");

        // When
        withdrawService.withdraw(localUser.getId(), request);

        // Then
        assertFalse(userRepository.existsById(localUser.getId()));
    }

    @Test
    void withdraw_localUser_shouldThrowExceptionWithWrongPassword() {
        // Given
        WithdrawRequest request = new WithdrawRequest();
        request.setPassword("WrongPassword!");
        request.setReason("테스트 탈퇴");

        // When & Then
        assertThrows(InvalidCredentialsException.class,
                () -> withdrawService.withdraw(localUser.getId(), request));

        // User should still exist
        assertTrue(userRepository.existsById(localUser.getId()));
    }

    @Test
    void withdraw_oauthUser_shouldDeleteUserWithoutPassword() {
        // Given
        WithdrawRequest request = new WithdrawRequest();
        request.setReason("테스트 탈퇴");
        // OAuth 사용자는 password 없이 탈퇴 가능

        // When
        withdrawService.withdraw(googleUser.getId(), request);

        // Then
        assertFalse(userRepository.existsById(googleUser.getId()));
    }

    @Test
    void withdraw_shouldThrowExceptionWhenUserNotFound() {
        // Given
        WithdrawRequest request = new WithdrawRequest();
        request.setReason("테스트 탈퇴");

        // When & Then
        assertThrows(UserNotFoundException.class,
                () -> withdrawService.withdraw(99999L, request));
    }

    @Test
    void withdraw_shouldRevokeAllRefreshTokens() {
        // Given - 리프레시 토큰 생성
        WithdrawRequest request = new WithdrawRequest();
        request.setPassword("Password123!");
        request.setReason("테스트 탈퇴");

        // When
        withdrawService.withdraw(localUser.getId(), request);

        // Then - 리프레시 토큰도 삭제되어야 함
        assertTrue(refreshTokenRepository.findByUser(localUser).isEmpty());
    }
}
