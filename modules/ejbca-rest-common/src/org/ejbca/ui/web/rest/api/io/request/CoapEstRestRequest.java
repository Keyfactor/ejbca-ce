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

import io.swagger.annotations.ApiModelProperty;

/**
 * A class representing the input for EST with Coap REST method.
 *
 */
public class CoapEstRestRequest {

    @ApiModelProperty(value = "Base64 encoded csr message", example = "MIIDXzCCA...eW1Zro0=")
    private String csr;

    @ApiModelProperty(value = "Birth Certificate", example = "MIIDXzCCA...eW1Zro0=")
    private String cert;

    public CoapEstRestRequest() {
    }

    public CoapEstRestRequest(String csr, String cert) {
        this.csr = csr;
        this.cert = cert;
    }

    public CoapEstRestRequest(String csr){
        this.csr = csr;
    }

    public String getCsr() {
        return csr;
    }

    public void setCsr(String csr) {
        this.csr = csr;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }
}
