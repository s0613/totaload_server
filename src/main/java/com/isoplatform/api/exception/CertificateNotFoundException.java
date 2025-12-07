package com.isoplatform.api.exception;

public class CertificateNotFoundException extends CertificateException {

    private final Long certificateId;

    public CertificateNotFoundException(Long id) {
        super("Certificate not found: " + id);
        this.certificateId = id;
    }

    public CertificateNotFoundException(String vin) {
        super("Certificate not found for VIN: " + vin);
        this.certificateId = null;
    }

    public Long getCertificateId() {
        return certificateId;
    }
}
