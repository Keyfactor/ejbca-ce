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
 * JSON input representation of key store enrollment
 * @version $Id: KeyStoreRestRequest.java 29481 2018-07-09 08:06:14Z henriks $
 *
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class) 
public class KeyStoreRestRequest {

    @Schema(description = "Username", example = "JohnDoe")
    private String username;
    @Schema(description = "Password", example = "foo123")
    private String password;
    @Schema(description = "Key algorithm used for enrollment", example = "RSA")
    private String keyAlg;
    @Schema(description = "Key specification to use", example = "4096")
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
