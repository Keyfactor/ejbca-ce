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
 * JSON input representation of crypto token key generation request through REST API.
 * @version $Id: CryptoTokenKeyGenerationRestRequest.java 32299 2019-05-08 13:23:48Z lauri_k_helmes $
 *
 */
public class CryptoTokenKeyGenerationRestRequest {

    @ApiModelProperty(value = "Key pair alias", example = "signKey")
    private String keyPairAlias;
    @ApiModelProperty(value = "Key algorithm", example = "RSA")
    private String keyAlg;
    @ApiModelProperty(value = "Key specification", example = "4096")
    private String keySpec;
    
    public CryptoTokenKeyGenerationRestRequest() {}

    public CryptoTokenKeyGenerationRestRequest(String keyPairAlias, String keyAlg, String keySpec) {
        this.keyPairAlias = keyPairAlias;
        this.keyAlg = keyAlg;
        this.keySpec = keySpec;
    }
    
    public String getKeyPairAlias() {
        return keyPairAlias;
    }

    public void setKeyPairAlias(String keyPairAlias) {
        this.keyPairAlias = keyPairAlias;
    }
    
    public String getKeyAlg() {
        return keyAlg;
    }

    public void setKeyAlg(String keyAlg) {
        this.keyAlg = keyAlg;
    }
    
    public String getKeySpec() {
        return keySpec;
    }

    public void setKeySpec(String keySpec) {
        this.keySpec = keySpec;
    }

}
