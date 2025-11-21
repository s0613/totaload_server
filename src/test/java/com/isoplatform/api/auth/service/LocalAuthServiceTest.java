package com.isoplatform.api.auth.service;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.dto.AuthResponse;
import com.isoplatform.api.auth.dto.LoginRequest;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.exception.EmailAlreadyExistsException;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.InvalidRefreshTokenException;
import com.isoplatform.api.auth.exception.OAuth2UserCannotLoginLocallyException;
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
class LocalAuthServiceTest {

    @Autowired
    private LocalAuthService localAuthService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        // Clean up any existing test data
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void signup_shouldCreateUserAndReturnTokens() {
        // Given
        SignupRequest request = new SignupRequest();
        request.setEmail("newuser@example.com");
        request.setPassword("Password123!");
        request.setName("New User");
        request.setCompany("Test Company");

        // When
        AuthResponse response = localAuthService.signup(request);

        // Then
        assertNotNull(response);
        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertNotNull(response.getExpiresIn());
        assertEquals("newuser@example.com", response.getEmail());
        assertEquals("New User", response.getName());
        assertEquals("USER", response.getRole());
        assertNotNull(response.getUserId());

        // Verify user saved in database
        User savedUser = userRepository.findByEmail("newuser@example.com").orElse(null);
        assertNotNull(savedUser);
        assertEquals("LOCAL", savedUser.getProvider());
        assertEquals("Test Company", savedUser.getCompany());
        assertTrue(passwordEncoder.matches("Password123!", savedUser.getPassword()));

        // Verify refresh token created
        RefreshToken refreshToken = refreshTokenRepository.findByToken(response.getRefreshToken()).orElse(null);
        assertNotNull(refreshToken);
        assertEquals(savedUser.getId(), refreshToken.getUser().getId());
    }

    @Test
    void signup_shouldThrowExceptionWhenEmailExists() {
        // Given
        SignupRequest request1 = new SignupRequest();
        request1.setEmail("duplicate@example.com");
        request1.setPassword("Password123!");
        request1.setName("User 1");

        localAuthService.signup(request1);

        // When
        SignupRequest request2 = new SignupRequest();
        request2.setEmail("duplicate@example.com");
        request2.setPassword("DifferentPass456!");
        request2.setName("User 2");

        // Then
        EmailAlreadyExistsException exception = assertThrows(
            EmailAlreadyExistsException.class,
            () -> localAuthService.signup(request2)
        );
        assertTrue(exception.getMessage().contains("Unable to complete registration"));
    }

    @Test
    void login_shouldReturnTokensForValidCredentials() {
        // Given - register a user first
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("login@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Login User");
        localAuthService.signup(signupRequest);

        // When
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("login@example.com");
        loginRequest.setPassword("Password123!");

        AuthResponse response = localAuthService.login(loginRequest);

        // Then
        assertNotNull(response);
        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals("login@example.com", response.getEmail());
        assertEquals("Login User", response.getName());
        assertEquals("USER", response.getRole());
    }

    @Test
    void login_shouldThrowExceptionForInvalidEmail() {
        // When
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("nonexistent@example.com");
        loginRequest.setPassword("Password123!");

        // Then
        InvalidCredentialsException exception = assertThrows(
            InvalidCredentialsException.class,
            () -> localAuthService.login(loginRequest)
        );
        assertTrue(exception.getMessage().contains("Invalid email or password"));
    }

    @Test
    void login_shouldThrowExceptionForInvalidPassword() {
        // Given
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("wrong@example.com");
        signupRequest.setPassword("CorrectPassword123!");
        signupRequest.setName("Wrong Password User");
        localAuthService.signup(signupRequest);

        // When
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("wrong@example.com");
        loginRequest.setPassword("WrongPassword!");

        // Then
        InvalidCredentialsException exception = assertThrows(
            InvalidCredentialsException.class,
            () -> localAuthService.login(loginRequest)
        );
        assertTrue(exception.getMessage().contains("Invalid email or password"));
    }

    @Test
    void login_shouldThrowExceptionForOAuth2User() {
        // Given - create an OAuth2 user directly
        User oauth2User = User.builder()
                .email("oauth@example.com")
                .password(passwordEncoder.encode("Password123!"))
                .name("OAuth User")
                .provider("GOOGLE")
                .providerId("google-123")
                .company("SELF")
                .role(Role.USER)
                .build();
        userRepository.save(oauth2User);

        // When
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("oauth@example.com");
        loginRequest.setPassword("Password123!");

        // Then
        OAuth2UserCannotLoginLocallyException exception = assertThrows(
            OAuth2UserCannotLoginLocallyException.class,
            () -> localAuthService.login(loginRequest)
        );
        assertTrue(exception.getMessage().contains("Please login with GOOGLE"));
    }

    @Test
    void refreshAccessToken_shouldReturnNewTokens() {
        // Given - register and get initial tokens
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("refresh@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Refresh User");
        AuthResponse initialResponse = localAuthService.signup(signupRequest);

        String oldRefreshToken = initialResponse.getRefreshToken();

        // When
        AuthResponse response = localAuthService.refreshAccessToken(oldRefreshToken);

        // Then
        assertNotNull(response);
        assertNotNull(response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        assertEquals("refresh@example.com", response.getEmail());
        assertEquals("Refresh User", response.getName());

        // New refresh token should be different (token rotation)
        assertNotEquals(oldRefreshToken, response.getRefreshToken());

        // Old refresh token should be revoked
        RefreshToken oldToken = refreshTokenRepository.findByToken(oldRefreshToken).orElse(null);
        assertNotNull(oldToken);
        assertTrue(oldToken.isRevoked());
    }

    @Test
    void refreshAccessToken_shouldThrowExceptionForInvalidToken() {
        // When
        String invalidToken = "invalid-refresh-token-123";

        // Then
        InvalidRefreshTokenException exception = assertThrows(
            InvalidRefreshTokenException.class,
            () -> localAuthService.refreshAccessToken(invalidToken)
        );
        assertTrue(exception.getMessage().contains("Invalid or expired refresh token"));
    }

    @Test
    void logout_shouldRevokeRefreshToken() {
        // Given - register and get tokens
        SignupRequest signupRequest = new SignupRequest();
        signupRequest.setEmail("logout@example.com");
        signupRequest.setPassword("Password123!");
        signupRequest.setName("Logout User");
        AuthResponse response = localAuthService.signup(signupRequest);

        String refreshToken = response.getRefreshToken();

        // When
        localAuthService.logout(refreshToken);

        // Then
        RefreshToken token = refreshTokenRepository.findByToken(refreshToken).orElse(null);
        assertNotNull(token);
        assertTrue(token.isRevoked());
    }
}
