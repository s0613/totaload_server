package com.isoplatform.api.exception;

import java.util.List;

/**
 * Exception thrown when AI image validation fails.
 * Contains details about which images failed validation.
 */
public class ImageValidationException extends RuntimeException {

    private final List<String> failedImages;

    public ImageValidationException(String message, List<String> failedImages) {
        super(message);
        this.failedImages = failedImages;
    }

    public ImageValidationException(String message, List<String> failedImages, Throwable cause) {
        super(message, cause);
        this.failedImages = failedImages;
    }

    public List<String> getFailedImages() {
        return failedImages;
    }
}
