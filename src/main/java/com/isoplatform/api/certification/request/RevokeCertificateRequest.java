package com.isoplatform.api.certification.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevokeCertificateRequest {
    private String reason;
    private String additionalNotes;
}
