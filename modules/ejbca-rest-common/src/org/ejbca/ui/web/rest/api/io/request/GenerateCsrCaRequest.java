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

import java.util.List;

import org.ejbca.ui.web.rest.api.validator.ValidGenerateCsrCaRequest;


/**
 * JSON input to generate CSR for a CA.
 */
@ValidGenerateCsrCaRequest
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class GenerateCsrCaRequest {
    
    public static final String GENERATE_NEW_KEY_INDICATOR = "GENERATE_NEW";

    @Schema(description = "Name of the key or keyAlias in CA's cryptotoken", example = "signKey or GENERATE_NEW")
    private String keyPair;
    @Schema(description = "Certificate Chain as PEM(Optional)")
    private List<String> certificateChain;
    @Schema(description = "Response format", example = "DER")
    private String responseFormat;
    
    public GenerateCsrCaRequest() {
        
    }
    
    public String getKeyPair() {
        return keyPair;
    }
    
    public void setKeyPair(String keyPair) {
        this.keyPair = keyPair;
    }
    
    public List<String> getCertificateChain() {
        return certificateChain;
    }
    
    public void setCertificateChain(List<String> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public String getResponseFormat() {
        return responseFormat != null ? responseFormat : "DER";
    }

    public void setResponseFormat(String responseFormat) {
        this.responseFormat = responseFormat;
    }
    
}
