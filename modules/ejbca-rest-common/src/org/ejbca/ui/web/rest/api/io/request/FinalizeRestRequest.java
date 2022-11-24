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
 * JSON input representation of finalize enrollment
 */
public class FinalizeRestRequest {

    @ApiModelProperty(value = "Response format", example = "P12", allowableValues = "P12, BCFKS, JKS, DER")
    private String responseFormat;
    @ApiModelProperty(value = "Password", example = "foo123")
    private String password;
    @ApiModelProperty(value = "Key algorithm", example = "RSA")
    private String keyAlg;
    @ApiModelProperty(value = "Key specification", example = "4096")
    private String keySpec;
    
    public FinalizeRestRequest() {}

    /**
     * Constructor used when key algorithm is pre-set in the end entity.
     * Example: Finalizing enrollment after a certificate request has approved. In this case the 
     * key algorithm has been picked from the CSR already.
     * @param responseFormat 'P12', 'JKS', 'PEM' or 'DER'
     * @param password End Entity password
     */
    public FinalizeRestRequest(String responseFormat, String password) {
        this.responseFormat = responseFormat;
        this.password = password;
    }

    /**
     * Constructor used when key algorithm isn't set in the end entity already. 
     * Example: Finalizing enrollment of an end entity after an "Add end entity approval"
     * @param responseFormat 'P12', 'JKS', 'PEM' or 'DER'
     * @param password End Entity password
     * @param keyAlg 'RSA', 'ECDSA' etc.
     * @param keySpec key size. E.g. '2048'
     */
    public FinalizeRestRequest(String responseFormat, String password, String keyAlg, String keySpec) {
        this.responseFormat = responseFormat;
        this.password = password;
        this.keyAlg = keyAlg;
        this.keySpec = keySpec;
    }
    
    public String getResponseFormat() {
        return responseFormat;
    }
    
    /**
     * @param responseFormat of the certificate or keystore. Must be one of
     * 'P12', 'JKS', 'PEM' or 'DER'
     */
    public void setResponseFormat(String responseFormat) {
        this.responseFormat = responseFormat;
    }
    
    public String getPassword() {
        return password;
    }
    
    /**
     * @param password used for inital request
     */
    public void setPassword(String password) {
        this.password = password;
    }

    public String getKeyAlg() {
        return this.keyAlg;
    }

    public void setKeyAlg(String keyAlg) {
        this.keyAlg = keyAlg;
    }

    public String getKeySpec() {
        return this.keySpec;
    }

    public void setKeySpec(String keySpec) {
        this.keySpec = keySpec;
    }
}
