package com.isoplatform.api.config;

import com.isoplatform.api.auth.exception.EmailAlreadyExistsException;
import com.isoplatform.api.auth.exception.InvalidCredentialsException;
import com.isoplatform.api.auth.exception.InvalidRefreshTokenException;
import com.isoplatform.api.auth.exception.OAuth2UserCannotLoginLocallyException;
import com.isoplatform.api.auth.dto.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test suite for GlobalExceptionHandler
 *
 * Tests centralized exception handling for:
 * - Authentication exceptions (401)
 * - Validation exceptions (400)
 * - Business logic exceptions (409, 400)
 * - System exceptions (500)
 */
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler exceptionHandler;

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
    }

    @Test
    void handleEmailAlreadyExists_shouldReturn409() {
        // Given
        EmailAlreadyExistsException exception = new EmailAlreadyExistsException("test@example.com");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleEmailAlreadyExists(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("EMAIL_EXISTS");
        assertThat(response.getBody().getMessage()).contains("test@example.com");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleInvalidCredentials_shouldReturn401() {
        // Given
        InvalidCredentialsException exception = new InvalidCredentialsException("Invalid email or password");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleInvalidCredentials(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(response.getBody().getMessage()).isEqualTo("Invalid email or password");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleOAuth2UserCannotLoginLocally_shouldReturn400() {
        // Given
        OAuth2UserCannotLoginLocallyException exception =
            new OAuth2UserCannotLoginLocallyException("User test@example.com registered via GOOGLE cannot login locally");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleOAuth2UserCannotLoginLocally(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("OAUTH2_USER");
        assertThat(response.getBody().getMessage()).contains("test@example.com");
        assertThat(response.getBody().getMessage()).contains("GOOGLE");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleInvalidRefreshToken_shouldReturn401() {
        // Given
        InvalidRefreshTokenException exception = new InvalidRefreshTokenException("Token has expired");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleInvalidRefreshToken(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("INVALID_TOKEN");
        assertThat(response.getBody().getMessage()).isEqualTo("Token has expired");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleValidationErrors_shouldReturn400() {
        // Given
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fieldError1 = new FieldError("signupRequest", "email", "must be a well-formed email address");
        FieldError fieldError2 = new FieldError("signupRequest", "password", "size must be between 8 and 100");

        when(bindingResult.getFieldErrors()).thenReturn(List.of(fieldError1, fieldError2));

        MethodArgumentNotValidException exception = new MethodArgumentNotValidException(null, bindingResult);

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleValidationErrors(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("VALIDATION_ERROR");
        assertThat(response.getBody().getMessage()).contains("email");
        assertThat(response.getBody().getMessage()).contains("password");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleHttpMessageNotReadable_shouldReturn400() {
        // Given
        HttpMessageNotReadableException exception =
            new HttpMessageNotReadableException("JSON parse error", (Throwable) null);

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleHttpMessageNotReadable(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("BAD_REQUEST");
        assertThat(response.getBody().getMessage()).isEqualTo("Malformed JSON request");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleIllegalArgument_shouldReturn400() {
        // Given
        IllegalArgumentException exception = new IllegalArgumentException("Invalid parameter");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleIllegalArgument(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("BAD_REQUEST");
        assertThat(response.getBody().getMessage()).isEqualTo("Invalid parameter");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleIllegalState_shouldReturn500() {
        // Given
        IllegalStateException exception = new IllegalStateException("Illegal state");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleIllegalState(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("INTERNAL_ERROR");
        assertThat(response.getBody().getMessage()).isEqualTo("An unexpected error occurred");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleGenericException_shouldReturn500() {
        // Given
        Exception exception = new Exception("Unexpected error");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleGenericException(exception);

        // Then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getError()).isEqualTo("INTERNAL_ERROR");
        assertThat(response.getBody().getMessage()).isEqualTo("An unexpected error occurred");
        assertThat(response.getBody().getTimestamp()).isNotNull();
    }

    @Test
    void handleGenericException_shouldNotLeakSensitiveInformation() {
        // Given - Exception with potentially sensitive information
        Exception exception = new Exception("Database connection failed: password=secret123");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleGenericException(exception);

        // Then - Should return generic message, not the actual exception message
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getMessage()).isEqualTo("An unexpected error occurred");
        assertThat(response.getBody().getMessage()).doesNotContain("password");
        assertThat(response.getBody().getMessage()).doesNotContain("secret123");
    }

    @Test
    void handleIllegalState_shouldNotLeakSensitiveInformation() {
        // Given - Exception with potentially sensitive information
        IllegalStateException exception = new IllegalStateException("User token: abc123xyz");

        // When
        ResponseEntity<ErrorResponse> response = exceptionHandler.handleIllegalState(exception);

        // Then - Should return generic message
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getMessage()).isEqualTo("An unexpected error occurred");
        assertThat(response.getBody().getMessage()).doesNotContain("token");
        assertThat(response.getBody().getMessage()).doesNotContain("abc123xyz");
    }
}
