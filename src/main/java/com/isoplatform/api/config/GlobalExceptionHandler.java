package com.isoplatform.api.config;

import com.isoplatform.api.auth.dto.ErrorResponse;
import com.isoplatform.api.auth.exception.EmailAlreadyExistsException;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.InvalidRefreshTokenException;
import com.isoplatform.api.auth.exception.OAuth2UserCannotLoginLocallyException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/**
 * Global exception handler for centralized error handling across all controllers.
 *
 * Provides consistent error responses for:
 * - Authentication exceptions (401)
 * - Validation exceptions (400)
 * - Business logic exceptions (409, 400)
 * - System exceptions (500)
 *
 * All error responses use ErrorResponse DTO with error code, message, and timestamp.
 * Client errors (4xx) are logged at WARN level.
 * Server errors (5xx) are logged at ERROR level with full stack trace.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handle EmailAlreadyExistsException
     *
     * @param ex the exception
     * @return 409 Conflict with error response
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleEmailAlreadyExists(EmailAlreadyExistsException ex) {
        log.warn("Email already exists: {}", ex.getMessage());
        ErrorResponse error = new ErrorResponse("EMAIL_EXISTS", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
    }

    /**
     * Handle InvalidCredentialsException
     *
     * @param ex the exception
     * @return 401 Unauthorized with error response
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex) {
        log.warn("Invalid credentials attempt: {}", ex.getMessage());
        ErrorResponse error = new ErrorResponse("INVALID_CREDENTIALS", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    /**
     * Handle OAuth2UserCannotLoginLocallyException
     *
     * @param ex the exception
     * @return 400 Bad Request with error response
     */
    @ExceptionHandler(OAuth2UserCannotLoginLocallyException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2UserCannotLoginLocally(OAuth2UserCannotLoginLocallyException ex) {
        log.warn("OAuth2 user attempted local login: {}", ex.getMessage());
        ErrorResponse error = new ErrorResponse("OAUTH2_USER", ex.getMessage());
        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle InvalidRefreshTokenException
     *
     * @param ex the exception
     * @return 401 Unauthorized with error response
     */
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefreshToken(InvalidRefreshTokenException ex) {
        log.warn("Invalid refresh token: {}", ex.getMessage());
        ErrorResponse error = new ErrorResponse("INVALID_TOKEN", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    /**
     * Handle validation errors from @Valid annotation
     *
     * @param ex the exception
     * @return 400 Bad Request with detailed validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));

        log.warn("Validation error: {}", errorMessage);
        ErrorResponse error = new ErrorResponse("VALIDATION_ERROR", errorMessage);
        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle malformed JSON requests
     *
     * @param ex the exception
     * @return 400 Bad Request with error response
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        log.warn("Malformed JSON request: {}", ex.getMessage());
        ErrorResponse error = new ErrorResponse("BAD_REQUEST", "Malformed JSON request");
        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle illegal argument exceptions
     *
     * @param ex the exception
     * @return 400 Bad Request with error response
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("Illegal argument: {}", ex.getMessage());
        ErrorResponse error = new ErrorResponse("BAD_REQUEST", ex.getMessage());
        return ResponseEntity.badRequest().body(error);
    }

    /**
     * Handle illegal state exceptions
     *
     * @param ex the exception
     * @return 500 Internal Server Error with generic message (does not leak sensitive information)
     */
    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<ErrorResponse> handleIllegalState(IllegalStateException ex) {
        log.error("Illegal state: {}", ex.getMessage(), ex);
        ErrorResponse error = new ErrorResponse("INTERNAL_ERROR", "An unexpected error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }

    /**
     * Handle all other unexpected exceptions
     *
     * @param ex the exception
     * @return 500 Internal Server Error with generic message (does not leak sensitive information)
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(Exception ex) {
        log.error("Unexpected exception: {}", ex.getMessage(), ex);
        ErrorResponse error = new ErrorResponse("INTERNAL_ERROR", "An unexpected error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
