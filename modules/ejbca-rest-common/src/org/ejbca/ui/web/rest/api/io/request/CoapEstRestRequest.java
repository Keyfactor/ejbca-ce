/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;

/**
 * A class to handle EST requests through CoAP. This REST resource is only used
 * by CoAP Proxy
 *
 */
public class CoapEstRestRequest {

    @ApiModelProperty(value = "Certificate Request", example = "MIIDXzCCA...eW1Zro0=")
    private String csr;

    @ApiModelProperty(value = "Certificate", example = "MIIDXzCCA...eW1Zro0=")
    private String cert;

    public CoapEstRestRequest() {
    }

    public CoapEstRestRequest(String csr, String cert) {
        this.csr = csr;
        this.cert = cert;
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
