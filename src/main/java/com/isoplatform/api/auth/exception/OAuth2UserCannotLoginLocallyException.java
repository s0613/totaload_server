package com.isoplatform.api.auth.exception;

public class OAuth2UserCannotLoginLocallyException extends RuntimeException {

    public OAuth2UserCannotLoginLocallyException(String message) {
        super(message);
    }

    public OAuth2UserCannotLoginLocallyException(String message, Throwable cause) {
        super(message, cause);
    }
}
