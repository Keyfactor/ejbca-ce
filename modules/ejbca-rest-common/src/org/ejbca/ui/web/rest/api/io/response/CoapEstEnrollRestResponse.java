/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.annotations.ApiModelProperty;

/**
 * A class representing the response for EST simpleenroll and simplereenroll requests with CoAP REST method.
 * Used for communicating with CoAP Proxy
 *
 */
public class CoapEstEnrollRestResponse {

    @ApiModelProperty(value = "Certificate", example = "MIIDXzCCA...eW1Zro0=")
    private String cert;

    public CoapEstEnrollRestResponse(String cert) {
        this.cert = cert;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }
}
