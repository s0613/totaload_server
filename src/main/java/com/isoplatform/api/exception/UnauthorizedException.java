package com.isoplatform.api.exception;

/**
 * Exception thrown when a user attempts to perform an action they are not authorized to do.
 * This differs from authentication (401) - user is authenticated but lacks permission.
 * Returns HTTP 403 Forbidden.
 */
public class UnauthorizedException extends RuntimeException {

    public UnauthorizedException(String message) {
        super(message);
    }
}
