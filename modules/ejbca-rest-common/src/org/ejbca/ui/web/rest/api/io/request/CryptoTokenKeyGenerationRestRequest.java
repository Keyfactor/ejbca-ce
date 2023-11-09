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
import io.swagger.annotations.ApiParam;

/**
 * JSON input representation of crypto token key generation request through REST API.
 */
public class CryptoTokenKeyGenerationRestRequest {

    @ApiModelProperty(value = "Key pair aliasof the key pair to be generated, must not already exist", example = "signKey")
    private String keyPairAlias;
    @ApiModelProperty(value = "Key algorithm, required for some algorithms, RSA, not required for others like EC or Dilithium", example = "RSA")
    private String keyAlg;
    @ApiModelProperty(value = "Key specification, key size, curve or name, must be supported by the underlying crypto token, like 4096 for RSA or secp256r1 for EC", example = "4096")
    private String keySpec;
    @ApiModelProperty(value = "Optional key usage, affects some crypto tokens (PKCS#11 NG) but not most others. Values SIGN, ENCRYPT, SIGN_ENCRYPT", example="SIGN")
    private String keyUsage;
    
    public CryptoTokenKeyGenerationRestRequest() {}

    public CryptoTokenKeyGenerationRestRequest(String keyPairAlias, String keyAlg, String keySpec, String keyUsage) {
        this.keyPairAlias = keyPairAlias;
        this.keyAlg = keyAlg;
        this.keySpec = keySpec;
        this.keyUsage = keyUsage;
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

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

}
