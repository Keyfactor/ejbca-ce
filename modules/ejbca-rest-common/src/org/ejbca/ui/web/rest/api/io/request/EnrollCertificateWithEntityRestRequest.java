/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.request;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import org.ejbca.ui.web.rest.api.validator.ValidEnrollCertificateWithEntityRestRequest;

@ValidEnrollCertificateWithEntityRestRequest
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class EnrollCertificateWithEntityRestRequest {

    @Schema(description = "Certificate request", example = "MIICh...V8shQ== OR -----BEGIN CERTIFICATE REQUEST-----\nMIICh...V8shQ==\n-----END CERTIFICATE REQUEST-----")
    private String certificateRequest;

    @Schema(description = "Key recoverable or not", example = "false", nullable = true)
    private Boolean includeChain;

    @Schema(description = "Certificate Request Type", example = "PUBLICKEY, PKCS10, CRMF, SPKAC, or CVC")
    private String certificateRequestType;

    @Schema(description = "Response Format (DER format is default)", example = "DER")
    private String responseFormat ="DER";

    @Valid
    private AddEndEntityRestRequest endEntity;

    public AddEndEntityRestRequest getEndEntity() {
        return endEntity;
    }

    public void setEndEntity(AddEndEntityRestRequest endEntity) {
        this.endEntity = endEntity;
    }

    public String getCertificateRequest() {
        return certificateRequest;
    }

    public void setCertificateRequest(String certificateRequest) {
        this.certificateRequest = certificateRequest;
    }

    public Boolean getIncludeChain() {
        return includeChain;
    }

    public void setIncludeChain(Boolean includeChain) {
        this.includeChain = includeChain;
    }

    public String getCertificateRequestType() {
        return certificateRequestType;
    }

    public void setCertificateRequestType(String certificateRequestType) {
        this.certificateRequestType = certificateRequestType;
    }

    public String getResponseFormat() {
        return responseFormat;
    }

    public void setResponseFormat(String responseFormat) {
        this.responseFormat = responseFormat;
    }
}
