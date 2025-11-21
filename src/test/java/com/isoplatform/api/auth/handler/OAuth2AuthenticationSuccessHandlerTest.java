package com.isoplatform.api.auth.handler;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.auth.service.JwtTokenProvider;
import com.isoplatform.api.auth.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationSuccessHandlerTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private UserRepository userRepository;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private RedirectStrategy redirectStrategy;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private OAuth2AuthenticationSuccessHandler handler;

    private User testUser;
    private RefreshToken testRefreshToken;

    @BeforeEach
    void setUp() {
        handler = new OAuth2AuthenticationSuccessHandler(
                jwtTokenProvider,
                refreshTokenService,
                userRepository
        );

        // Inject frontend URL via reflection
        ReflectionTestUtils.setField(handler, "frontendUrl", "http://localhost:3000");

        // Set custom redirect strategy for testing
        handler.setRedirectStrategy(redirectStrategy);

        // Set up test user
        testUser = User.builder()
                .id(1L)
                .email("test@example.com")
                .name("Test User")
                .role(Role.USER)
                .provider("GOOGLE")
                .build();

        // Set up test refresh token
        testRefreshToken = RefreshToken.builder()
                .id(1L)
                .user(testUser)
                .token("refresh-token-123")
                .expiryDate(LocalDateTime.now().plusDays(7))
                .revoked(false)
                .build();
    }

    @Test
    void onAuthenticationSuccess_shouldGenerateTokens() throws IOException {
        // Given
        OAuth2User oAuth2User = createOAuth2User("test@example.com", "Test User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtTokenProvider.generateToken(testUser)).thenReturn("jwt-access-token-123");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn(null);

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        verify(jwtTokenProvider).generateToken(testUser);
        verify(refreshTokenService).createRefreshToken(testUser);
    }

    @Test
    void onAuthenticationSuccess_shouldRedirectToMobileDeepLink() throws IOException {
        // Given
        String mobileDeepLink = "totaload://oauth2/callback";
        OAuth2User oAuth2User = createOAuth2User("test@example.com", "Test User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtTokenProvider.generateToken(testUser)).thenReturn("jwt-access-token-123");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn(mobileDeepLink);

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(redirectStrategy).sendRedirect(eq(request), eq(response), urlCaptor.capture());

        String redirectUrl = urlCaptor.getValue();
        assertThat(redirectUrl).startsWith(mobileDeepLink);
        assertThat(redirectUrl).contains("access_token=jwt-access-token-123");
        assertThat(redirectUrl).contains("refresh_token=refresh-token-123");
        assertThat(redirectUrl).contains("token_type=Bearer");
    }

    @Test
    void onAuthenticationSuccess_shouldRedirectToDefaultUrlWithoutRedirectParam() throws IOException {
        // Given
        OAuth2User oAuth2User = createOAuth2User("test@example.com", "Test User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtTokenProvider.generateToken(testUser)).thenReturn("jwt-access-token-123");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn(null);

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(redirectStrategy).sendRedirect(eq(request), eq(response), urlCaptor.capture());

        String redirectUrl = urlCaptor.getValue();
        assertThat(redirectUrl).startsWith("http://localhost:3000");
        assertThat(redirectUrl).contains("access_token=jwt-access-token-123");
        assertThat(redirectUrl).contains("refresh_token=refresh-token-123");
        assertThat(redirectUrl).contains("token_type=Bearer");
    }

    @Test
    void onAuthenticationSuccess_shouldCreateOrUpdateUser() throws IOException {
        // Given - User exists
        OAuth2User oAuth2User = createOAuth2User("existing@example.com", "Existing User");
        Authentication authentication = createAuthentication(oAuth2User);

        User existingUser = User.builder()
                .id(2L)
                .email("existing@example.com")
                .name("Existing User")
                .role(Role.USER)
                .provider("GOOGLE")
                .build();

        when(userRepository.findByEmail("existing@example.com")).thenReturn(Optional.of(existingUser));
        when(jwtTokenProvider.generateToken(existingUser)).thenReturn("jwt-token");
        when(refreshTokenService.createRefreshToken(existingUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn(null);

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        verify(userRepository).findByEmail("existing@example.com");
        verify(jwtTokenProvider).generateToken(existingUser);
    }

    @Test
    void onAuthenticationSuccess_shouldThrowExceptionWhenUserNotFound() {
        // Given
        OAuth2User oAuth2User = createOAuth2User("nonexistent@example.com", "New User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        // When/Then
        assertThrows(RuntimeException.class, () -> {
            handler.onAuthenticationSuccess(request, response, authentication);
        });
    }

    @Test
    void onAuthenticationSuccess_shouldHandleEmptyRedirectUrl() throws IOException {
        // Given
        OAuth2User oAuth2User = createOAuth2User("test@example.com", "Test User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtTokenProvider.generateToken(testUser)).thenReturn("jwt-access-token-123");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn("");

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(redirectStrategy).sendRedirect(eq(request), eq(response), urlCaptor.capture());

        String redirectUrl = urlCaptor.getValue();
        assertThat(redirectUrl).startsWith("http://localhost:3000");
    }

    @Test
    void onAuthenticationSuccess_shouldIncludeTokenTypeInRedirect() throws IOException {
        // Given
        OAuth2User oAuth2User = createOAuth2User("test@example.com", "Test User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtTokenProvider.generateToken(testUser)).thenReturn("jwt-access-token-123");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn(null);

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(redirectStrategy).sendRedirect(eq(request), eq(response), urlCaptor.capture());

        String redirectUrl = urlCaptor.getValue();
        assertThat(redirectUrl).contains("token_type=Bearer");
    }

    @Test
    void onAuthenticationSuccess_shouldHandleCustomMobileDeepLink() throws IOException {
        // Given
        String customDeepLink = "myapp://auth/callback";
        OAuth2User oAuth2User = createOAuth2User("test@example.com", "Test User");
        Authentication authentication = createAuthentication(oAuth2User);

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testUser));
        when(jwtTokenProvider.generateToken(testUser)).thenReturn("jwt-access-token-123");
        when(refreshTokenService.createRefreshToken(testUser)).thenReturn(testRefreshToken);
        when(request.getParameter("redirectUrl")).thenReturn(customDeepLink);

        // When
        handler.onAuthenticationSuccess(request, response, authentication);

        // Then
        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        verify(redirectStrategy).sendRedirect(eq(request), eq(response), urlCaptor.capture());

        String redirectUrl = urlCaptor.getValue();
        assertThat(redirectUrl).startsWith(customDeepLink);
        assertThat(redirectUrl).contains("access_token=jwt-access-token-123");
        assertThat(redirectUrl).contains("refresh_token=refresh-token-123");
    }

    // Helper methods
    private OAuth2User createOAuth2User(String email, String name) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("email", email);
        attributes.put("name", name);
        attributes.put("sub", "google-user-id-123");

        return new DefaultOAuth2User(
                java.util.Collections.emptyList(),
                attributes,
                "email"
        );
    }

    private Authentication createAuthentication(OAuth2User oAuth2User) {
        return new OAuth2AuthenticationToken(
                oAuth2User,
                oAuth2User.getAuthorities(),
                "google"
        );
    }
}
