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
 * JSON input representation of key store enrollment
 * @version $Id: KeyStoreRestRequest.java 29481 2018-07-09 08:06:14Z henriks $
 *
 */
public class KeyStoreRestRequest {

    private String username;
    private String password;
    @ApiModelProperty(value = "Key algorithm used for enrollment",
        example = "RSA, DSA, ECDSA")
    private String keyAlg;
    @ApiModelProperty(value = "Key specification to use",
        example = "1024, 2048, secp256r1 (for ECDSA)")
    private String keySpec;
    
    public KeyStoreRestRequest() {}
    
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
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