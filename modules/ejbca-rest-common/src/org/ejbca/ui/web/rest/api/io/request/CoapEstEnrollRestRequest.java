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

import io.swagger.annotations.ApiModelProperty;

/**
 * A class to handle EST simpleenroll and simplereenroll requests through CoAP. This REST resource is only used
 * by CoAP Proxy
 *
 */
public class CoapEstEnrollRestRequest {

    @ApiModelProperty(value = "Certificate Request", example = "MIIDXzCCA...eW1Zro0=")
    private String csr;

    @JsonAlias({"tlsCertificate", "tls_certificate"})
    @ApiModelProperty(value = "DTLS Certificate", example = "MIIDXzCCA...eW1Zro0=")
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
