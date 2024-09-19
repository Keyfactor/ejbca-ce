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

/**
 * JSON input representation of crypto token activation request through REST API.
 * @version $Id: CryptoTokenActivationRestRequest.java 32242 2019-04-30 15:30:51Z henriks $
 *
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class) 
public class CryptoTokenActivationRestRequest {

    @Schema(description = "Activation Code", example = "foo123")
    private String activationCode;
    
    public CryptoTokenActivationRestRequest() {}

    public CryptoTokenActivationRestRequest(String activationCode) {
        this.activationCode = activationCode;
    }
    
    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

}
