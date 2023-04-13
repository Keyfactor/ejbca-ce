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

import io.swagger.annotations.ApiModelProperty;

/**
 * A class containing a public key in SSH format
 *
 */
public class SshPublicKeyRestResponse {

    @ApiModelProperty(value = "Certificate Authority (CA) name", example = "CN=ExampleCA")
    private final String caName;
    @ApiModelProperty(value = "CA’s public key", example = "ssh-rsa AAAAB...QxLwx SshCA")
    private final String response;

    public SshPublicKeyRestResponse(final String caName, final String response) {
        this.caName = caName;
        this.response = response;
    }


    public String getCaName() {
        return caName;
    }


    public String getResponse() {
        return response;
    }
  
}
