package com.isoplatform.api.exception;

public class UserNotAuthenticatedException extends RuntimeException {

    public UserNotAuthenticatedException() {
        super("User not authenticated");
    }

    public UserNotAuthenticatedException(String message) {
        super(message);
    }
}
