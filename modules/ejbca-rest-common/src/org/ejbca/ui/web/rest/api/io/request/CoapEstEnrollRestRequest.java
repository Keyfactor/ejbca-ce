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

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import io.swagger.v3.oas.annotations.media.Schema;


/**
 * A class to handle EST simpleenroll and simplereenroll requests through CoAP. This REST resource is only used
 * by CoAP Proxy
 *
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class) 
public class CoapEstEnrollRestRequest {

    @Schema(description = "Certificate Request", example = "MIIDXzCCA...eW1Zro0=")
    private String csr;

    @JsonAlias({"tlsCertificate", "tls_certificate"})
    @Schema(description = "DTLS Certificate", example = "MIIDXzCCA...eW1Zro0=")
    private String tlsCertificate;

    public CoapEstEnrollRestRequest() {
    }

    public CoapEstEnrollRestRequest(String csr, String tlsCertificate) {
        this.csr = csr;
        this.tlsCertificate = tlsCertificate;
    }

    public String getCsr() {
        return csr;
    }

    public void setCsr(String csr) {
        this.csr = csr;
    }

    public String getTlsCertificate() {
        return tlsCertificate;
    }

    public void setTlsCertificate(String tlsCertificate) {
        this.tlsCertificate = tlsCertificate;
    }
}
