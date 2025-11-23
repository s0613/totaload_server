package com.isoplatform.api.auth.controller;

import com.isoplatform.api.auth.RefreshToken;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.dto.AuthResponse;
import com.isoplatform.api.auth.dto.LoginRequest;
import com.isoplatform.api.auth.dto.MobileTokenRequest;
import com.isoplatform.api.auth.dto.MobileTokenResponse;
import com.isoplatform.api.auth.dto.RefreshTokenRequest;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.repository.RefreshTokenRepository;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.auth.service.GoogleTokenService;
import com.isoplatform.api.auth.service.JwtTokenProvider;
import com.isoplatform.api.auth.service.LocalAuthService;
import com.isoplatform.api.auth.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final LocalAuthService localAuthService;
    private final GoogleTokenService googleTokenService;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * Register a new user with email and password
     *
     * @param request signup request containing email, password, and name
     * @return 201 Created with authentication tokens
     */
    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
        log.info("Signup request for email: {}", request.getEmail());
        AuthResponse response = localAuthService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Login with email and password
     *
     * @param request login request containing email and password
     * @return 200 OK with authentication tokens
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request for email: {}", request.getEmail());
        AuthResponse response = localAuthService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Refresh access token using refresh token
     *
     * @param request refresh token request
     * @return 200 OK with new authentication tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request");
        AuthResponse response = localAuthService.refreshAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    /**
     * Logout by revoking refresh token
     *
     * @param request refresh token request
     * @return 200 OK on successful logout
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Logout request");
        localAuthService.logout(request.getRefreshToken());
        return ResponseEntity.ok().build();
    }

    /**
     * Logout from all devices by revoking all refresh tokens
     * Requires valid access token in Authorization header
     *
     * @param authentication Spring Security authentication (from JWT)
     * @return 200 OK on successful logout
     */
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.warn("Unauthorized logout-all attempt");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }

        String email = authentication.getName();
        log.info("Logout-all request for user: {}", email);

        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        refreshTokenService.revokeAllUserTokens(user);

        return ResponseEntity.ok().build();
    }

    /**
     * Mobile token exchange - Google auth code to JWT
     * Used by mobile apps with PKCE flow
     * NOTE: redirectUri is server-configured for security (not from client)
     */
    @PostMapping("/mobile/token")
    public ResponseEntity<MobileTokenResponse> mobileTokenExchange(
            @Valid @RequestBody MobileTokenRequest request) {
        try {
            log.info("Mobile token exchange request received");

            // 1. Exchange Google auth code for Google tokens (using server-configured redirect URI)
            GoogleTokenService.GoogleTokenResponse googleTokens = googleTokenService.exchangeCodeForTokensMobile(
                request.getAuthorizationCode(),
                request.getCodeVerifier()
            );

            // 2. Verify Google ID token and extract user info (mobile audience)
            GoogleTokenService.GoogleUserInfo googleUser = googleTokenService.verifyIdTokenMobile(
                googleTokens.getIdToken()
            );

            // 3. Find or create user (using sub as providerId, NOT email)
            User user = userRepository.findByProviderAndProviderId("GOOGLE", googleUser.getSub())
                .orElseGet(() -> {
                    User newUser = User.builder()
                        .email(googleUser.getEmail())
                        .provider("GOOGLE")
                        .providerId(googleUser.getSub())
                        .name(googleUser.getName())
                        .password("")  // OAuth users don't have password
                        .role(Role.USER)
                        .company("SELF")
                        .build();
                    return userRepository.save(newUser);
                });

            // 4. Update email if changed (email can change, sub cannot)
            String googleEmail = googleUser.getEmail();
            if (googleEmail != null && !googleEmail.equals(user.getEmail())) {
                user.setEmail(googleEmail);
                userRepository.save(user);
            }

            // 5. Generate JWT access token
            String accessToken = jwtTokenProvider.generateToken(user);

            // 6. Generate and store refresh token in DB (7 days)
            String refreshTokenValue = UUID.randomUUID().toString();
            RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenValue)
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .build();
            refreshTokenRepository.save(refreshToken);

            log.info("Mobile token exchange successful for user: {}", user.getEmail());

            return ResponseEntity.ok(MobileTokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .expiresIn(900)  // 15 minutes in seconds
                .email(user.getEmail())
                .name(user.getName())
                .build());

        } catch (Exception e) {
            log.error("Mobile token exchange failed: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token exchange failed");
        }
    }
}
