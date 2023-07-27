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

package org.ejbca.ui.web.rest.api.io.response;

import com.fasterxml.jackson.annotation.JsonAlias;
import io.swagger.annotations.ApiModelProperty;

import java.util.List;

/**
 * A class representing the response for EST Alias Configuration requests with CoAP REST method, to discover
 * configured EST aliases.
 *
 * Used for communicating with CoAP Proxy
 */
public class CoapEstAliasConfigurationRestResponse {
    private String name;
    @JsonAlias({"vendorCaCertificates", "vendor_ca_certificates" })
    @ApiModelProperty(value = "Vendor CA Certificate (PEM)", example = "MIIDXzCCA...eW1Zro0=")
    private List<String> vendorCaCertificates;

    @JsonAlias({"signingCaCertificate", "signing_ca_certificate" })
    @ApiModelProperty(value = "Signing CA Certificate (PEM)", example = "MIIDXzCCA...eW1Zro0=")
    private String signingCaCertificate;

    @JsonAlias({"signingCaCertificateChain", "signing_ca_certificate_chain" })
    @ApiModelProperty(value = "Signing CA Certificate Chain", example = "MIIDXzCCA...eW1Zro0=")
    private String signingCaCertificateChain;

    @JsonAlias({"supportServerKeyGeneration", "support_server_key_generation" })
    @ApiModelProperty(value = "Is serverside key generation supported", example = "true")
    private boolean supportServerKeyGeneration;

    public CoapEstAliasConfigurationRestResponse() {}

    public CoapEstAliasConfigurationRestResponse(String name, List<String> vendorCaCertificates, String signingCaCertificate, String signingCaCertificateChain, boolean supportServerKeyGeneration) {
        this.name = name;
        this.vendorCaCertificates = vendorCaCertificates;
        this.signingCaCertificate = signingCaCertificate;
        this.signingCaCertificateChain = signingCaCertificateChain;
        this.supportServerKeyGeneration = supportServerKeyGeneration;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getVendorCaCertificates() {
        return vendorCaCertificates;
    }

    public void setVendorCaCertificates(List<String> vendorCaCertificates) {
        this.vendorCaCertificates = vendorCaCertificates;
    }

    public String getSigningCaCertificate() {
        return signingCaCertificate;
    }

    public void setSigningCaCertificate(String signingCaCertificate) {
        this.signingCaCertificate = signingCaCertificate;
    }

    public String getSigningCaCertificateChain() {
        return signingCaCertificateChain;
    }

    public void setSigningCaCertificateChain(String signingCaCertificateChain) {
        this.signingCaCertificateChain = signingCaCertificateChain;
    }

    public boolean isSupportServerKeyGeneration() {
        return supportServerKeyGeneration;
    }

    public void setSupportServerKeyGeneration(boolean supportServerKeyGeneration) {
        this.supportServerKeyGeneration = supportServerKeyGeneration;
    }
}
