package com.isoplatform.api.auth.controller;

import com.isoplatform.api.auth.dto.AuthResponse;
import com.isoplatform.api.auth.dto.LoginRequest;
import com.isoplatform.api.auth.dto.RefreshTokenRequest;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.service.LocalAuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final LocalAuthService localAuthService;

    /**
     * Register a new user with email and password
     *
     * @param request signup request containing email, password, and name
     * @return 201 Created with authentication tokens
     */
    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
        try {
            log.info("Signup request for email: {}", request.getEmail());
            AuthResponse response = localAuthService.signup(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (RuntimeException e) {
            log.error("Signup failed: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Login with email and password
     *
     * @param request login request containing email and password
     * @return 200 OK with authentication tokens
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            log.info("Login request for email: {}", request.getEmail());
            AuthResponse response = localAuthService.login(request);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Login failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    /**
     * Refresh access token using refresh token
     *
     * @param request refresh token request
     * @return 200 OK with new authentication tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            log.info("Token refresh request");
            AuthResponse response = localAuthService.refreshAccessToken(request.getRefreshToken());
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            log.error("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    /**
     * Logout by revoking refresh token
     *
     * @param request refresh token request
     * @return 204 No Content on successful logout
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            log.info("Logout request");
            localAuthService.logout(request.getRefreshToken());
            return ResponseEntity.noContent().build();
        } catch (RuntimeException e) {
            log.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
