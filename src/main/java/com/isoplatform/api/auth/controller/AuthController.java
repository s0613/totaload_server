package com.isoplatform.api.auth.controller;

import com.isoplatform.api.auth.dto.AuthResponse;
import com.isoplatform.api.auth.dto.ErrorResponse;
import com.isoplatform.api.auth.dto.LoginRequest;
import com.isoplatform.api.auth.dto.RefreshTokenRequest;
import com.isoplatform.api.auth.dto.SignupRequest;
import com.isoplatform.api.auth.exception.EmailAlreadyExistsException;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.InvalidRefreshTokenException;
import com.isoplatform.api.auth.exception.OAuth2UserCannotLoginLocallyException;
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
     * Handle EmailAlreadyExistsException
     *
     * @param e the exception
     * @return 409 Conflict with error response
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailExists(EmailAlreadyExistsException e) {
        log.error("Email already exists: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse("EMAIL_EXISTS", e.getMessage()));
    }

    /**
     * Handle InvalidCredentialsException
     *
     * @param e the exception
     * @return 401 Unauthorized with error response
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException e) {
        log.error("Invalid credentials: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("INVALID_CREDENTIALS", e.getMessage()));
    }

    /**
     * Handle OAuth2UserCannotLoginLocallyException
     *
     * @param e the exception
     * @return 400 Bad Request with error response
     */
    @ExceptionHandler(OAuth2UserCannotLoginLocallyException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2User(OAuth2UserCannotLoginLocallyException e) {
        log.error("OAuth2 user attempted local login: {}", e.getMessage());
        return ResponseEntity.badRequest()
                .body(new ErrorResponse("OAUTH2_USER", e.getMessage()));
    }

    /**
     * Handle InvalidRefreshTokenException
     *
     * @param e the exception
     * @return 401 Unauthorized with error response
     */
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefreshToken(InvalidRefreshTokenException e) {
        log.error("Invalid refresh token: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("INVALID_TOKEN", e.getMessage()));
    }
}
